package scoring

import (
	"net/url"
	"testing"
	"time"

	"ssrf-detector/internal/core"
)

func TestBuildFindingSetsFusionAndReportFlags(t *testing.T) {
	scorer := NewScorer(core.DefaultConfig())
	targetURL, _ := url.Parse("https://example.com/fetch?url=test")

	state := &core.ScanState{
		Target: &core.Target{
			URL:    targetURL,
			Method: "GET",
			InjectionPoint: core.InjectionPoint{
				Type: core.InjectionQuery,
				Name: "url",
			},
		},
		Evidence: []core.Evidence{
			&core.OOBCallbackEvidence{
				Callback: &core.OOBCallback{
					IsTargetInfrastructure: true,
					SourceIP:               "10.0.0.10",
				},
				Verified: true,
			},
			&core.CloudMetadataEvidence{
				Provider:      "AWS",
				Endpoint:      "http://169.254.169.254",
				DataRetrieved: "i-1234567890abcdef0",
			},
			&core.TimingAnomalyEvidence{
				Samples:      12,
				ZScore:       5.0,
				BaselineMean: 100 * time.Millisecond,
				TestDuration: 2400 * time.Millisecond,
			},
		},
		PhaseResults: map[core.DetectionPhase]*core.PhaseResult{
			core.PhaseFetchAnalysis: {
				Metadata: map[string]interface{}{
					"port_restrictions": map[string]bool{
						"port_80":   true,
						"port_6379": false,
					},
				},
			},
		},
		Metadata: map[string]interface{}{},
	}

	finding, err := scorer.BuildFinding(state)
	if err != nil {
		t.Fatalf("expected finding, got error: %v", err)
	}

	if finding.BlindFusionScore <= 0 {
		t.Fatalf("expected blind fusion score to be set, got %.2f", finding.BlindFusionScore)
	}
	if !finding.ReportReady {
		t.Fatalf("expected report-ready finding")
	}
	if finding.CVSS <= 0 {
		t.Fatalf("expected CVSS to be set from chain reasoning")
	}
	if len(finding.AttackChains) == 0 {
		t.Fatalf("expected at least one attack chain")
	}
}
