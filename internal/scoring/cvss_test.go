package scoring

import (
	"strings"
	"testing"

	"ssrf-detector/internal/core"
)

func TestComputeCVSSAWSMetadataFinding(t *testing.T) {
	f := &ScoredFinding{
		Finding: &core.Finding{
			Type:          core.VulnTypeCloudMetadata,
			CloudProvider: "AWS",
			AttackChains: []core.AttackChain{
				{Title: "SSRF → AWS credential theft"},
			},
		},
	}

	score, vector := ComputeCVSS(f)
	if score < 9.0 {
		t.Fatalf("expected CVSS >= 9.0, got %.1f", score)
	}
	if !strings.Contains(vector, "/S:C/") {
		t.Fatalf("expected scope changed vector, got %s", vector)
	}
	if !strings.Contains(vector, "/C:H/") {
		t.Fatalf("expected high confidentiality impact, got %s", vector)
	}
}

func TestComputeCVSSBlindSSRFOnly(t *testing.T) {
	f := &ScoredFinding{
		Finding: &core.Finding{
			Type: core.VulnTypeBlindSSRF,
		},
	}

	score, vector := ComputeCVSS(f)
	if score < 5.0 || score >= 8.0 {
		t.Fatalf("expected CVSS in 5.x-7.x range, got %.1f", score)
	}
	if !strings.Contains(vector, "/S:U/") {
		t.Fatalf("expected unchanged scope vector, got %s", vector)
	}
	if !strings.Contains(vector, "/C:N/") {
		t.Fatalf("expected no confidentiality impact for blind-only finding, got %s", vector)
	}
}

func TestComputeCVSSRCEChainFinding(t *testing.T) {
	f := &ScoredFinding{
		Finding: &core.Finding{
			Type: core.VulnTypeProtocolEscalation,
			AttackChains: []core.AttackChain{
				{Title: "SSRF → Redis RCE (gopher path)"},
			},
		},
	}

	score, _ := ComputeCVSS(f)
	if score < 9.5 {
		t.Fatalf("expected CVSS >= 9.5, got %.1f", score)
	}
}
