// Package report implements report generation in various formats.
package report

import (
	"encoding/json"
	"time"

	"ssrf-detector/internal/core"
)

// JSONReporter generates JSON reports
type JSONReporter struct {
	config *core.Config
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(config *core.Config) *JSONReporter {
	return &JSONReporter{
		config: config,
	}
}

func (r *JSONReporter) Format() string {
	return "json"
}

// Generate creates a JSON report
func (r *JSONReporter) Generate(findings []*core.Finding, state *core.ScanState) ([]byte, error) {
	report := &JSONReport{
		Version:     "1.0",
		GeneratedAt: time.Now(),
		Scanner: ScannerInfo{
			Name:    "SSRF Detector",
			Version: "1.0.0",
		},
		Target: TargetInfo{
			URL:    state.Target.URL.String(),
			Method: state.Target.Method,
		},
		Summary:  r.buildSummary(findings, state),
		Findings: r.buildFindings(findings),
		Scan: ScanInfo{
			StartTime: state.StartTime,
			Duration:  time.Since(state.StartTime),
			Phases:    r.buildPhasesSummary(state),
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

// JSONReport structure
type JSONReport struct {
	Version     string      `json:"version"`
	GeneratedAt time.Time   `json:"generated_at"`
	Scanner     ScannerInfo `json:"scanner"`
	Target      TargetInfo  `json:"target"`
	Summary     Summary     `json:"summary"`
	Findings    []Finding   `json:"findings"`
	Scan        ScanInfo    `json:"scan"`
}

type ScannerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type TargetInfo struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

type Summary struct {
	TotalFindings     int            `json:"total_findings"`
	BySeverity        map[string]int `json:"by_severity"`
	ByConfidence      map[string]int `json:"by_confidence"`
	ByType            map[string]int `json:"by_type"`
	HighestSeverity   string         `json:"highest_severity"`
	HasCloudMetadata  bool           `json:"has_cloud_metadata"`
	HasInternalAccess bool           `json:"has_internal_access"`
}

type Finding struct {
	ID                  string            `json:"id"`
	Type                string            `json:"type"`
	Severity            string            `json:"severity"`
	Confidence          string            `json:"confidence"`
	ConfidenceScore     int               `json:"confidence_score"`
	VulnerableParameter string            `json:"vulnerable_parameter"`
	Impact              string            `json:"impact"`
	Evidence            []EvidenceSummary `json:"evidence"`
	InternalIPsReached  []string          `json:"internal_ips_reached,omitempty"`
	CloudProvider       string            `json:"cloud_provider,omitempty"`
	DetectedAt          time.Time         `json:"detected_at"`
	ProofOfConcept      string            `json:"proof_of_concept,omitempty"`
	Remediation         string            `json:"remediation"`
}

type EvidenceSummary struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Score       int         `json:"score"`
	Timestamp   time.Time   `json:"timestamp"`
	Data        interface{} `json:"data,omitempty"`
}

type ScanInfo struct {
	StartTime time.Time      `json:"start_time"`
	Duration  time.Duration  `json:"duration"`
	Phases    []PhaseSummary `json:"phases"`
}

type PhaseSummary struct {
	Name          string        `json:"name"`
	Success       bool          `json:"success"`
	Duration      time.Duration `json:"duration"`
	EvidenceCount int           `json:"evidence_count"`
}

// buildSummary creates summary section
func (r *JSONReporter) buildSummary(findings []*core.Finding, state *core.ScanState) Summary {
	summary := Summary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByConfidence:  make(map[string]int),
		ByType:        make(map[string]int),
	}

	highestSeverity := core.SeverityLow

	for _, finding := range findings {
		// Count by severity
		summary.BySeverity[string(finding.Severity)]++

		// Track highest severity
		if r.isSeverityHigher(finding.Severity, highestSeverity) {
			highestSeverity = finding.Severity
		}

		// Count by confidence
		summary.ByConfidence[string(finding.Confidence)]++

		// Count by type
		summary.ByType[string(finding.Type)]++

		// Check for critical findings
		if finding.Type == core.VulnTypeCloudMetadata {
			summary.HasCloudMetadata = true
		}
		if finding.Type == core.VulnTypeInternalSSRF {
			summary.HasInternalAccess = true
		}
	}

	summary.HighestSeverity = string(highestSeverity)

	return summary
}

// buildFindings converts findings to JSON format
func (r *JSONReporter) buildFindings(findings []*core.Finding) []Finding {
	result := make([]Finding, 0, len(findings))

	for _, f := range findings {
		finding := Finding{
			ID:                  f.ID,
			Type:                string(f.Type),
			Severity:            string(f.Severity),
			Confidence:          string(f.Confidence),
			ConfidenceScore:     f.ConfidenceScore,
			VulnerableParameter: f.VulnerableParameter,
			Impact:              f.Impact,
			InternalIPsReached:  f.InternalIPsReached,
			CloudProvider:       f.CloudProvider,
			DetectedAt:          f.DetectedAt,
			ProofOfConcept:      f.ProofOfConcept,
			Remediation:         f.Remediation,
		}

		// Convert evidence
		finding.Evidence = make([]EvidenceSummary, 0, len(f.Evidence))
		for _, ev := range f.Evidence {
			evSummary := EvidenceSummary{
				Type:        string(ev.Type()),
				Description: ev.Description(),
				Score:       ev.Score(),
				Timestamp:   ev.Timestamp(),
				Data:        ev.Data(),
			}
			finding.Evidence = append(finding.Evidence, evSummary)
		}

		result = append(result, finding)
	}

	return result
}

// buildPhasesSummary creates phases summary
func (r *JSONReporter) buildPhasesSummary(state *core.ScanState) []PhaseSummary {
	phases := make([]PhaseSummary, 0)

	for phase, result := range state.PhaseResults {
		summary := PhaseSummary{
			Name:          string(phase),
			Success:       result.Success,
			Duration:      result.Duration,
			EvidenceCount: len(result.Evidence),
		}
		phases = append(phases, summary)
	}

	return phases
}

// isSeverityHigher compares severities
func (r *JSONReporter) isSeverityHigher(s1, s2 core.Severity) bool {
	severityRank := map[core.Severity]int{
		core.SeverityCritical: 4,
		core.SeverityHigh:     3,
		core.SeverityMedium:   2,
		core.SeverityLow:      1,
		core.SeverityInfo:     0,
	}

	return severityRank[s1] > severityRank[s2]
}
