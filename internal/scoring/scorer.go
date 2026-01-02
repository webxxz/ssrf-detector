// Package scoring implements confidence and severity scoring for findings.
package scoring

import (
	"fmt"
	"time"

	"ssrf-detector/internal/core"
)

// Scorer calculates confidence scores and severity levels
type Scorer struct {
	config *core.Config
}

// NewScorer creates a new scorer
func NewScorer(config *core.Config) *Scorer {
	return &Scorer{
		config: config,
	}
}

// CalculateConfidence computes confidence score from evidence
func (s *Scorer) CalculateConfidence(evidence []core.Evidence) (int, core.ConfidenceLevel) {
	totalScore := 0

	for _, ev := range evidence {
		score := ev.Score()

		// Disqualifying evidence immediately sets score to invalid
		if ev.IsDisqualifying() {
			return 0, core.ConfidenceNone
		}

		totalScore += score
	}

	// Determine confidence level
	var level core.ConfidenceLevel
	switch {
	case totalScore >= 80:
		level = core.ConfidenceHigh
	case totalScore >= 50:
		level = core.ConfidenceMedium
	case totalScore >= 20:
		level = core.ConfidenceLow
	default:
		level = core.ConfidenceNone
	}

	return totalScore, level
}

// CalculateSeverity determines severity based on vulnerability type and evidence
func (s *Scorer) CalculateSeverity(vulnType core.VulnerabilityType, evidence []core.Evidence, state *core.ScanState) core.Severity {
	// Base severity by vulnerability type
	baseSeverity := s.getBaseSeverity(vulnType)

	// Escalate based on evidence
	severity := baseSeverity

	for _, ev := range evidence {
		switch ev.Type() {
		case core.EvidenceCloudMetadata:
			// Cloud metadata is always critical
			return core.SeverityCritical

		case core.EvidenceInternalAccess:
			// Internal access escalates to at least High
			if severity < core.SeverityHigh {
				severity = core.SeverityHigh
			}

			// Check if sensitive service accessed
			if internalEv, ok := ev.(*core.InternalAccessEvidence); ok {
				if internalEv.ServiceResponse != "" {
					// Got actual response from internal service
					severity = core.SeverityCritical
				}
			}

		case core.EvidenceProtocolEscalation:
			// Protocol escalation (e.g., file://) is critical
			if protocolEv, ok := ev.(*ProtocolEscalationEvidence); ok {
				if protocolEv.Protocol == "file" && protocolEv.Supported {
					return core.SeverityCritical
				}
			}
		}
	}

	return severity
}

// getBaseSeverity returns base severity for vulnerability type
func (s *Scorer) getBaseSeverity(vulnType core.VulnerabilityType) core.Severity {
	switch vulnType {
	case core.VulnTypeCloudMetadata:
		return core.SeverityCritical

	case core.VulnTypeInternalSSRF:
		return core.SeverityHigh

	case core.VulnTypeSSRF, core.VulnTypeRedirectToSSRF:
		return core.SeverityHigh

	case core.VulnTypeBlindSSRF:
		return core.SeverityMedium

	case core.VulnTypeProtocolEscalation:
		return core.SeverityCritical

	case core.VulnTypeOpenRedirect:
		return core.SeverityMedium

	default:
		return core.SeverityLow
	}
}

// ClassifyVulnerability determines the vulnerability type from evidence
func (s *Scorer) ClassifyVulnerability(evidence []core.Evidence, state *core.ScanState) core.VulnerabilityType {
	hasCloudMetadata := false
	hasInternalAccess := false
	hasOOB := false
	hasRedirect := false
	hasProtocolEscalation := false
	serverSideRedirect := false

	for _, ev := range evidence {
		switch ev.Type() {
		case core.EvidenceCloudMetadata:
			hasCloudMetadata = true

		case core.EvidenceInternalAccess:
			hasInternalAccess = true

		case core.EvidenceOOBCallback:
			hasOOB = true

		case core.EvidenceRedirectFollowing:
			hasRedirect = true

		case core.EvidenceProtocolEscalation:
			hasProtocolEscalation = true
		}
	}

	// Check state for redirect capabilities
	if state.Capabilities != nil {
		if state.Capabilities["server_side_redirect"] {
			serverSideRedirect = true
		}
	}

	// Classification priority
	if hasCloudMetadata {
		return core.VulnTypeCloudMetadata
	}

	if hasProtocolEscalation {
		return core.VulnTypeProtocolEscalation
	}

	if hasInternalAccess {
		return core.VulnTypeInternalSSRF
	}

	if serverSideRedirect && hasOOB {
		return core.VulnTypeRedirectToSSRF
	}

	if hasOOB {
		return core.VulnTypeSSRF
	}

	if hasRedirect {
		return core.VulnTypeOpenRedirect
	}

	// Timing-only evidence
	hasTimingAnomaly := false
	for _, ev := range evidence {
		if ev.Type() == core.EvidenceTimingAnomaly {
			hasTimingAnomaly = true
			break
		}
	}

	if hasTimingAnomaly {
		return core.VulnTypeBlindSSRF
	}

	return core.VulnTypeSSRF // Default
}

// BuildFinding creates a Finding from scan state
func (s *Scorer) BuildFinding(state *core.ScanState) (*core.Finding, error) {
	if len(state.Evidence) == 0 {
		return nil, fmt.Errorf("no evidence to build finding")
	}

	// Calculate confidence
	score, confidence := s.CalculateConfidence(state.Evidence)

	// Reject if confidence is too low
	if confidence == core.ConfidenceNone {
		return nil, fmt.Errorf("confidence too low (score: %d)", score)
	}

	// Classify vulnerability
	vulnType := s.ClassifyVulnerability(state.Evidence, state)

	// Calculate severity
	severity := s.CalculateSeverity(vulnType, state.Evidence, state)

	// Build finding
	finding := &core.Finding{
		ID:              generateFindingID(),
		Type:            vulnType,
		Severity:        severity,
		Confidence:      confidence,
		ConfidenceScore: score,
		Target:          state.Target,
		Evidence:        state.Evidence,
		DetectedAt:      time.Now(),
	}

	// Extract details from evidence
	finding.VulnerableParameter = state.Target.InjectionPoint.Name

	// Build impact description
	finding.Impact = s.buildImpactDescription(vulnType, state.Evidence, state)

	// Build remediation guidance
	finding.Remediation = s.buildRemediation(vulnType)

	// Extract internal IPs if any
	finding.InternalIPsReached = s.extractInternalIPs(state.Evidence)

	// Detect cloud provider
	finding.CloudProvider = s.detectCloudProvider(state)

	// Phase where detected
	finding.PhaseDetected = s.findDetectionPhase(state)

	return finding, nil
}

// buildImpactDescription creates impact description
func (s *Scorer) buildImpactDescription(vulnType core.VulnerabilityType, evidence []core.Evidence, state *core.ScanState) string {
	switch vulnType {
	case core.VulnTypeCloudMetadata:
		return "Server-side request forgery allows access to cloud metadata service. " +
			"This can expose IAM credentials, instance metadata, and enable privilege escalation."

	case core.VulnTypeInternalSSRF:
		internalIPs := s.extractInternalIPs(evidence)
		return fmt.Sprintf("Server-side request forgery allows access to internal network. "+
			"Accessible IP addresses: %v. This enables internal service enumeration and potential exploitation.",
			internalIPs)

	case core.VulnTypeProtocolEscalation:
		return "Server-side request forgery with protocol escalation. " +
			"Non-HTTP protocols (file://, gopher://, etc.) can be used to read local files or interact with internal services."

	case core.VulnTypeRedirectToSSRF:
		return "Open redirect can be escalated to SSRF. The server follows redirects server-side, " +
			"allowing an attacker to redirect requests to internal resources."

	case core.VulnTypeSSRF:
		return "Server-side request forgery allows making requests to arbitrary external URLs. " +
			"This can be used for port scanning, service enumeration, and potential internal network access."

	case core.VulnTypeBlindSSRF:
		return "Blind server-side request forgery detected via timing analysis. " +
			"While responses are not returned, the server makes requests to attacker-controlled URLs."

	case core.VulnTypeOpenRedirect:
		return "Open redirect allows redirecting users to arbitrary external URLs. " +
			"This can be used for phishing attacks and OAuth token theft."

	default:
		return "Vulnerability detected in URL handling."
	}
}

// buildRemediation creates remediation guidance
func (s *Scorer) buildRemediation(vulnType core.VulnerabilityType) string {
	baseRemediation := "1. Implement strict URL validation with whitelist of allowed domains\n" +
		"2. Validate URLs after all decoding/parsing stages\n" +
		"3. Use the same URL parser for validation and fetching\n" +
		"4. Disable or restrict URL redirects\n"

	switch vulnType {
	case core.VulnTypeCloudMetadata:
		return baseRemediation +
			"5. Block access to cloud metadata IPs (169.254.169.254) at application and network level\n" +
			"6. Upgrade to IMDSv2 (AWS) which requires token authentication\n" +
			"7. Apply principle of least privilege to IAM roles\n"

	case core.VulnTypeInternalSSRF:
		return baseRemediation +
			"5. Block RFC1918 IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)\n" +
			"6. Block localhost/loopback (127.0.0.0/8, ::1)\n" +
			"7. Block link-local addresses (169.254.0.0/16)\n" +
			"8. Implement network segmentation and egress filtering\n"

	case core.VulnTypeProtocolEscalation:
		return baseRemediation +
			"5. Restrict URL schemes to http:// and https:// only\n" +
			"6. Disable support for file://, gopher://, dict://, and other protocols\n" +
			"7. Use HTTP client libraries with limited protocol support\n"

	default:
		return baseRemediation
	}
}

// extractInternalIPs extracts internal IPs from evidence
func (s *Scorer) extractInternalIPs(evidence []core.Evidence) []string {
	ips := make([]string, 0)
	seen := make(map[string]bool)

	for _, ev := range evidence {
		if internalEv, ok := ev.(*core.InternalAccessEvidence); ok {
			if !seen[internalEv.InternalIP] {
				ips = append(ips, internalEv.InternalIP)
				seen[internalEv.InternalIP] = true
			}
		}
	}

	return ips
}

// detectCloudProvider detects cloud provider from evidence
func (s *Scorer) detectCloudProvider(state *core.ScanState) string {
	for _, ev := range state.Evidence {
		if cloudEv, ok := ev.(*core.CloudMetadataEvidence); ok {
			return cloudEv.Provider
		}
	}

	return ""
}

// findDetectionPhase finds which phase detected the vulnerability
func (s *Scorer) findDetectionPhase(state *core.ScanState) core.DetectionPhase {
	// Find phase with most significant evidence
	phaseScores := make(map[core.DetectionPhase]int)

	for phase, result := range state.PhaseResults {
		if result.Success && len(result.Evidence) > 0 {
			score := 0
			for _, ev := range result.Evidence {
				score += ev.Score()
			}
			phaseScores[phase] = score
		}
	}

	// Find highest scoring phase
	var maxPhase core.DetectionPhase
	maxScore := 0

	for phase, score := range phaseScores {
		if score > maxScore {
			maxScore = score
			maxPhase = phase
		}
	}

	return maxPhase
}

// generateFindingID generates a unique finding ID
func generateFindingID() string {
	return fmt.Sprintf("SSRF-%d", time.Now().Unix())
}

// Additional evidence type for protocol escalation
type ProtocolEscalationEvidence struct {
	Protocol     string
	ErrorPattern string
	Supported    bool
	timestamp    time.Time
}

func (e *ProtocolEscalationEvidence) Type() core.EvidenceType {
	return core.EvidenceProtocolEscalation
}

func (e *ProtocolEscalationEvidence) Score() int {
	if e.Supported {
		return 40
	}
	return 10
}

func (e *ProtocolEscalationEvidence) Description() string {
	return fmt.Sprintf("Protocol %s: %s", e.Protocol, e.ErrorPattern)
}

func (e *ProtocolEscalationEvidence) Data() interface{} {
	return map[string]interface{}{
		"protocol":  e.Protocol,
		"supported": e.Supported,
	}
}

func (e *ProtocolEscalationEvidence) Timestamp() time.Time {
	return e.timestamp
}

func (e *ProtocolEscalationEvidence) IsDisqualifying() bool {
	return false
}
