package report

import (
	"fmt"
	"strings"
	"time"

	"ssrf-detector/internal/core"
)

// MarkdownReporter generates Markdown reports for bug bounty submissions
type MarkdownReporter struct {
	config *core.Config
}

// NewMarkdownReporter creates a new Markdown reporter
func NewMarkdownReporter(config *core.Config) *MarkdownReporter {
	return &MarkdownReporter{
		config: config,
	}
}

func (r *MarkdownReporter) Format() string {
	return "markdown"
}

// Generate creates a Markdown report
func (r *MarkdownReporter) Generate(findings []*core.Finding, state *core.ScanState) ([]byte, error) {
	var sb strings.Builder

	// Title
	sb.WriteString("# SSRF Detection Report\n\n")

	// Metadata
	sb.WriteString(fmt.Sprintf("**Generated**: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Target**: %s\n", state.Target.URL.String()))
	sb.WriteString(fmt.Sprintf("**Scan Duration**: %s\n\n", time.Since(state.StartTime)))

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	summary := r.buildTextSummary(findings)
	sb.WriteString(summary)
	sb.WriteString("\n\n")

	// Findings
	sb.WriteString("## Findings\n\n")

	if len(findings) == 0 {
		sb.WriteString("No vulnerabilities detected.\n\n")
	} else {
		for i, finding := range findings {
			sb.WriteString(r.formatFinding(i+1, finding))
			sb.WriteString("\n---\n\n")
		}
	}

	// Recommendations
	sb.WriteString("## Recommendations\n\n")
	sb.WriteString(r.buildRecommendations(findings))
	sb.WriteString("\n")

	return []byte(sb.String()), nil
}

// buildTextSummary creates executive summary
func (r *MarkdownReporter) buildTextSummary(findings []*core.Finding) string {
	if len(findings) == 0 {
		return "No vulnerabilities were detected during the scan."
	}

	var sb strings.Builder

	// Count by severity
	severityCounts := make(map[core.Severity]int)
	for _, f := range findings {
		severityCounts[f.Severity]++
	}

	sb.WriteString(fmt.Sprintf("Total vulnerabilities found: **%d**\n\n", len(findings)))

	if count := severityCounts[core.SeverityCritical]; count > 0 {
		sb.WriteString(fmt.Sprintf("- 🔴 **Critical**: %d\n", count))
	}
	if count := severityCounts[core.SeverityHigh]; count > 0 {
		sb.WriteString(fmt.Sprintf("- 🟠 **High**: %d\n", count))
	}
	if count := severityCounts[core.SeverityMedium]; count > 0 {
		sb.WriteString(fmt.Sprintf("- 🟡 **Medium**: %d\n", count))
	}
	if count := severityCounts[core.SeverityLow]; count > 0 {
		sb.WriteString(fmt.Sprintf("- 🟢 **Low**: %d\n", count))
	}

	return sb.String()
}

// formatFinding formats a single finding
func (r *MarkdownReporter) formatFinding(num int, finding *core.Finding) string {
	var sb strings.Builder

	// Header
	severityEmoji := r.getSeverityEmoji(finding.Severity)
	sb.WriteString(fmt.Sprintf("### %d. %s %s\n\n", num, severityEmoji, finding.Type))

	// Metadata table
	sb.WriteString("| Property | Value |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| **Severity** | %s |\n", finding.Severity))
	sb.WriteString(fmt.Sprintf("| **Confidence** | %s (%d/100) |\n", finding.Confidence, finding.ConfidenceScore))
	sb.WriteString(fmt.Sprintf("| **Vulnerable Parameter** | `%s` |\n", finding.VulnerableParameter))
	if finding.CloudProvider != "" {
		sb.WriteString(fmt.Sprintf("| **Cloud Provider** | %s |\n", finding.CloudProvider))
	}
	sb.WriteString(fmt.Sprintf("| **Detected At** | %s |\n", finding.DetectedAt.Format(time.RFC3339)))
	sb.WriteString("\n")

	// Description
	sb.WriteString("#### Description\n\n")
	sb.WriteString(finding.Impact)
	sb.WriteString("\n\n")

	// Evidence
	sb.WriteString("#### Evidence\n\n")
	for i, ev := range finding.Evidence {
		sb.WriteString(fmt.Sprintf("%d. **%s** (Score: %d)\n", i+1, ev.Type(), ev.Score()))
		sb.WriteString(fmt.Sprintf("   - %s\n", ev.Description()))
	}
	sb.WriteString("\n")

	// Internal IPs if any
	if len(finding.InternalIPsReached) > 0 {
		sb.WriteString("#### Internal IPs Accessed\n\n")
		for _, ip := range finding.InternalIPsReached {
			sb.WriteString(fmt.Sprintf("- `%s`\n", ip))
		}
		sb.WriteString("\n")
	}

	// Proof of Concept
	if finding.ProofOfConcept != "" {
		sb.WriteString("#### Proof of Concept\n\n")
		sb.WriteString("```http\n")
		sb.WriteString(finding.ProofOfConcept)
		sb.WriteString("\n```\n\n")
	}

	// Remediation
	sb.WriteString("#### Remediation\n\n")
	sb.WriteString(finding.Remediation)
	sb.WriteString("\n")

	return sb.String()
}

// buildRecommendations creates recommendations section
func (r *MarkdownReporter) buildRecommendations(findings []*core.Finding) string {
	if len(findings) == 0 {
		return "Continue monitoring for SSRF vulnerabilities in new features and endpoints."
	}

	var sb strings.Builder

	sb.WriteString("Based on the findings, the following actions are recommended:\n\n")

	// Check for critical issues
	hasCritical := false
	for _, f := range findings {
		if f.Severity == core.SeverityCritical {
			hasCritical = true
			break
		}
	}

	if hasCritical {
		sb.WriteString("### Immediate Actions Required\n\n")
		sb.WriteString("1. **Address Critical vulnerabilities immediately**\n")
		sb.WriteString("   - Block cloud metadata endpoints (169.254.169.254)\n")
		sb.WriteString("   - Implement emergency patches for credential exposure risks\n\n")
	}

	sb.WriteString("### General Recommendations\n\n")
	sb.WriteString("1. Implement strict URL validation with domain whitelisting\n")
	sb.WriteString("2. Validate URLs after all decoding stages\n")
	sb.WriteString("3. Use the same URL parser for validation and fetching\n")
	sb.WriteString("4. Block internal IP ranges (RFC1918, localhost, link-local)\n")
	sb.WriteString("5. Disable or restrict URL redirects\n")
	sb.WriteString("6. Implement network segmentation and egress filtering\n")
	sb.WriteString("7. Regular security testing for SSRF vulnerabilities\n")

	return sb.String()
}

// getSeverityEmoji returns emoji for severity
func (r *MarkdownReporter) getSeverityEmoji(severity core.Severity) string {
	switch severity {
	case core.SeverityCritical:
		return "🔴"
	case core.SeverityHigh:
		return "🟠"
	case core.SeverityMedium:
		return "🟡"
	case core.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}
