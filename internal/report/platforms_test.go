package report

import (
	"strings"
	"testing"

	"ssrf-detector/internal/core"
)

func TestRenderForPlatformHackerOne(t *testing.T) {
	out := RenderForPlatform(&ScoredFinding{
		Finding: &core.Finding{
			Type:   core.VulnTypeSSRF,
			Impact: "Server-side request forgery",
			CVSS:   8.1,
		},
	}, HackerOne)
	if !strings.Contains(out, "## Impact") {
		t.Fatalf("unexpected output: %s", out)
	}
}
