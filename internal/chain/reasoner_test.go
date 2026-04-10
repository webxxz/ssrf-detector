package chain

import (
	"testing"

	"ssrf-detector/internal/core"
)

func TestReasonChainsAWSMetadata(t *testing.T) {
	finding := &core.Finding{
		Type:          core.VulnTypeCloudMetadata,
		CloudProvider: "AWS",
		Evidence: []core.Evidence{
			&core.CloudMetadataEvidence{
				Provider: "AWS",
			},
		},
	}

	chains := ReasonChains(finding)
	if len(chains) == 0 {
		t.Fatalf("expected at least one chain")
	}
	if chains[0].CVSS < 9.0 {
		t.Fatalf("expected high CVSS chain, got %.1f", chains[0].CVSS)
	}
}
