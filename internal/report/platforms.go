package report

import (
	"fmt"
	"strings"
	"time"

	"ssrf-detector/internal/ai"
	"ssrf-detector/internal/core"
	"ssrf-detector/internal/scoring"
)

type Platform string

const (
	HackerOne Platform = "hackerone"
	Bugcrowd  Platform = "bugcrowd"
	Intigriti Platform = "intigriti"
	QNAP      Platform = "qnap"
)

type ScoredFinding struct {
	Finding *core.Finding
}

func RenderForPlatform(finding *ScoredFinding, p Platform) string {
	if finding == nil || finding.Finding == nil {
		return ""
	}
	f := finding.Finding
	score, vector := scoring.ComputeCVSS(&scoring.ScoredFinding{Finding: f})
	if aiReport, err := ai.WriteTriageReport(&ai.ScoredFinding{
		Finding:    f,
		CVSSScore:  score,
		CVSSVector: vector,
	}, ai.Platform(strings.ToLower(string(p)))); err == nil && strings.TrimSpace(aiReport) != "" {
		return aiReport
	}

	switch p {
	case HackerOne:
		return renderHackerOne(f)
	case Bugcrowd:
		return renderBugcrowd(f)
	case Intigriti:
		return renderIntigriti(f)
	case QNAP:
		return renderQNAP(f)
	default:
		return renderHackerOne(f)
	}
}

type PlatformMarkdownReporter struct {
	config   *core.Config
	platform Platform
}

func NewPlatformMarkdownReporter(config *core.Config, platform Platform) *PlatformMarkdownReporter {
	return &PlatformMarkdownReporter{config: config, platform: platform}
}

func (r *PlatformMarkdownReporter) Format() string { return "markdown" }

func (r *PlatformMarkdownReporter) Generate(findings []*core.Finding, state *core.ScanState) ([]byte, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# SSRF Report (%s)\n\n", r.platform))
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))
	if state != nil && state.Target != nil && state.Target.URL != nil {
		sb.WriteString(fmt.Sprintf("Target: %s\n\n", state.Target.URL.String()))
	}

	if len(findings) == 0 {
		sb.WriteString("No findings detected.\n")
		return []byte(sb.String()), nil
	}
	for i := range findings {
		sb.WriteString(RenderForPlatform(&ScoredFinding{Finding: findings[i]}, r.platform))
		sb.WriteString("\n---\n\n")
	}
	return []byte(sb.String()), nil
}

func renderHackerOne(f *core.Finding) string {
	score, vector := scoring.ComputeCVSS(&scoring.ScoredFinding{Finding: f})
	return fmt.Sprintf("## Impact\n%s\n\n## Steps\n%s\n\n## Supporting Material\n- CWE-918\n- CVSS: %.1f\n- CVSS Vector: %s\n", f.Impact, proofOrPlaceholder(f), score, vector)
}

func renderBugcrowd(f *core.Finding) string {
	score, vector := scoring.ComputeCVSS(&scoring.ScoredFinding{Finding: f})
	return fmt.Sprintf("## Bug URL\n%s\n\n## Vulnerability Details\nType: %s\nCWE: CWE-918\nCVSS: %.1f\nCVSS Vector: %s\n\n## Reproduction Steps\n%s\n", targetOrPlaceholder(f), f.Type, score, vector, proofOrPlaceholder(f))
}

func renderIntigriti(f *core.Finding) string {
	score, vector := scoring.ComputeCVSS(&scoring.ScoredFinding{Finding: f})
	return fmt.Sprintf("## Summary\n%s\n\n## Technical Details\n- Type: %s\n- Severity: %s\n- CVSS: %.1f\n- CVSS Vector: %s\n\n## Proof of Concept\n%s\n", f.Impact, f.Type, f.Severity, score, vector, proofOrPlaceholder(f))
}

func renderQNAP(f *core.Finding) string {
	score, vector := scoring.ComputeCVSS(&scoring.ScoredFinding{Finding: f})
	return fmt.Sprintf("## QNAP Security Bounty Submission\n- Affected Component: %s\n- Firmware Version: unknown\n- CWE: CWE-918\n- CVSS: %.1f\n- CVSS Vector: %s\n\n## Impact\n%s\n\n## Steps to Reproduce\n%s\n\n## CVE Request\nPlease evaluate for CVE assignment.\n", f.Type, score, vector, f.Impact, proofOrPlaceholder(f))
}

func targetOrPlaceholder(f *core.Finding) string {
	if f.Target != nil && f.Target.URL != nil {
		return f.Target.URL.String()
	}
	return "(target unavailable)"
}

func proofOrPlaceholder(f *core.Finding) string {
	if strings.TrimSpace(f.ProofOfConcept) != "" {
		return f.ProofOfConcept
	}
	return "1. Send crafted URL payload to vulnerable parameter.\n2. Observe server-side outbound request/callback.\n3. Validate SSRF impact and accessible resources."
}
