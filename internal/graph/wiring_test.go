package graph

import (
	"net/url"
	"testing"

	"ssrf-detector/internal/core"
	"ssrf-detector/internal/scoring"
)

func TestBuildGraphAndFindAttackPathsForRCEChain(t *testing.T) {
	u, err := url.Parse("https://example.com/fetch?url=test")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}

	f := &core.Finding{
		Target:              &core.Target{URL: u},
		VulnerableParameter: "url",
		InternalIPsReached:  []string{"127.0.0.1"},
		AttackChains: []core.AttackChain{
			{Title: "SSRF -> Redis RCE", Impact: "Remote code execution", CVSS: 9.0},
		},
		ConfidenceScore: 90,
	}

	g := BuildGraph([]*scoring.ScoredFinding{{Finding: f, RCEChain: true}})
	if g == nil || len(g.Nodes) == 0 || len(g.Edges) == 0 {
		t.Fatalf("expected non-empty graph, nodes=%d edges=%d", len(g.Nodes), len(g.Edges))
	}

	paths := FindAttackPaths(g)
	if len(paths) == 0 {
		t.Fatal("expected at least one attack path")
	}

	foundRCE := false
	for _, p := range paths {
		if p.Impact == "RCE" {
			foundRCE = true
			if p.CVSS < 9.0 {
				t.Fatalf("expected high cvss path for RCE, got %.1f", p.CVSS)
			}
		}
	}
	if !foundRCE {
		t.Fatalf("expected an RCE attack path, got %+v", paths)
	}
}
