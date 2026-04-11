package report

import (
	"strings"
	"testing"

	"ssrf-detector/internal/core"
)

func TestRenderForPlatformFallsBackWhenAIUnavailable(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")

	out := RenderForPlatform(&ScoredFinding{
		Finding: &core.Finding{
			Type:   core.VulnTypeSSRF,
			Impact: "Server-side request forgery",
		},
	}, HackerOne)

	if !strings.Contains(out, "## Impact") {
		t.Fatalf("expected static fallback content, got: %s", out)
	}
}
