package ai

import (
	"fmt"
	"strings"

	"ssrf-detector/internal/core"
)

// Platform identifies bug bounty report format.
type Platform string

const (
	PlatformHackerOne Platform = "hackerone"
	PlatformBugcrowd  Platform = "bugcrowd"
	PlatformIntigriti Platform = "intigriti"
	PlatformQNAP      Platform = "qnap"
)

// ScoredFinding is the AI report input shape.
type ScoredFinding struct {
	Finding    *core.Finding
	CVSSScore  float64
	CVSSVector string
}

// WriteTriageReport generates a platform-formatted report with Claude.
func WriteTriageReport(finding *ScoredFinding, platform Platform) (string, error) {
	if finding == nil || finding.Finding == nil {
		return "", fmt.Errorf("finding is required")
	}

	f := finding.Finding
	endpoint := "(unknown)"
	if f.Target != nil && f.Target.URL != nil {
		endpoint = f.Target.URL.String()
	}

	score := finding.CVSSScore
	vector := finding.CVSSVector
	if score <= 0 {
		score = f.CVSS
	}
	chainTitles := make([]string, 0, len(f.AttackChains))
	for _, c := range f.AttackChains {
		chainTitles = append(chainTitles, c.Title)
	}

	evidence := make([]string, 0, len(f.Evidence))
	for _, ev := range f.Evidence {
		evidence = append(evidence, ev.Description())
	}

	internalServices := make([]string, 0)
	for _, ev := range f.Evidence {
		data := strings.ToLower(ev.Description())
		if strings.Contains(data, "redis") || strings.Contains(data, "kube") || strings.Contains(data, "elastic") || strings.Contains(data, "jenkins") {
			internalServices = append(internalServices, ev.Description())
		}
	}

	prompt := fmt.Sprintf(`You are a professional bug bounty report writer.
Write a %s submission for this SSRF finding:

Endpoint: %s
Parameter: %s
Confidence: %s
CVSS: %.1f (%s)
Chains: %s
Evidence: %s
Internal Services Found: %s

Requirements:
- Write in professional security researcher tone
- Include exact reproduction steps with curl commands
- Calculate real business impact based on chains found
- Format for %s markdown requirements
- Do NOT exaggerate — only claim what evidence supports`,
		platform,
		endpoint,
		f.VulnerableParameter,
		f.Confidence,
		score,
		vector,
		strings.Join(chainTitles, " | "),
		strings.Join(evidence, " | "),
		strings.Join(internalServices, " | "),
		platform,
	)

	system := "You write accurate, concise, evidence-grounded security reports for bug bounty platforms."
	report, err := callClaude(system, prompt, 1400)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(report), nil
}
