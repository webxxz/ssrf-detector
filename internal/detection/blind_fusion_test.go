package detection

import (
	"testing"
	"time"

	"ssrf-detector/internal/core"
)

func TestFuseBlindSignals(t *testing.T) {
	score := FuseBlindSignals(&BlindSSRFSignals{
		OOBCallback: &OOBResult{Received: true},
		TimingDelta: 3000,
		PortOracle:  &PortScanResult{BehaviorDiffers: true},
		ErrorDiff:   0.6,
		SizeDelta:   250,
	})

	if score.Level != FusionConfirmed {
		t.Fatalf("expected CONFIRMED, got %s", score.Level)
	}
	if score.Score < 0.95 {
		t.Fatalf("expected score >= 0.95, got %.2f", score.Score)
	}
}

func TestBuildBlindSignalsFromState(t *testing.T) {
	state := &core.ScanState{
		Evidence: []core.Evidence{
			&core.OOBCallbackEvidence{
				Callback: &core.OOBCallback{
					IsTargetInfrastructure: true,
				},
				Verified: true,
			},
			&core.TimingAnomalyEvidence{
				BaselineMean: 100 * time.Millisecond,
				TestDuration: 2500 * time.Millisecond,
			},
		},
		Metadata: map[string]interface{}{
			"baseline_profile": &BaselineProfile{
				StatusCode:   200,
				ResponseSize: 1000,
				ResponseTime: 100 * time.Millisecond,
			},
		},
		PhaseResults: map[core.DetectionPhase]*core.PhaseResult{
			core.PhaseReachability: {
				Metadata: map[string]interface{}{
					"error_pattern": "Connection refused",
				},
			},
			core.PhaseFetchAnalysis: {
				Metadata: map[string]interface{}{
					"port_restrictions": map[string]bool{
						"port_80":   true,
						"port_6379": false,
					},
				},
			},
		},
	}

	signals := BuildBlindSignals(state)
	if !signals.OOBCallback.Received {
		t.Fatalf("expected OOB signal")
	}
	if signals.TimingDelta <= 0 {
		t.Fatalf("expected timing delta")
	}
	if signals.PortOracle == nil || !signals.PortOracle.BehaviorDiffers {
		t.Fatalf("expected port oracle behavior diff")
	}
}
