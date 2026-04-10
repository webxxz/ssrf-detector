package scoring

import (
	"testing"
	"time"

	"ssrf-detector/internal/core"
)

func TestCalculateConfidenceUsesCorrelationBonus(t *testing.T) {
	scorer := NewScorer(core.DefaultConfig())
	evidence := []core.Evidence{
		&core.OOBCallbackEvidence{
			Callback: &core.OOBCallback{
				SourceIP:               "10.0.0.10",
				IsTargetInfrastructure: true,
			},
			Verified: true,
		},
		&core.TimingAnomalyEvidence{
			Samples:      12,
			ZScore:       4.2,
			BaselineMean: 100 * time.Millisecond,
			TestDuration: 900 * time.Millisecond,
		},
	}

	score, confidence := scorer.CalculateConfidence(evidence)
	if score <= 60 {
		t.Fatalf("expected bonus-adjusted score > 60, got %d", score)
	}
	if confidence == core.ConfidenceNone {
		t.Fatalf("expected non-empty confidence, got %s", confidence)
	}
}

func TestCalculateConfidenceRejectsDisqualifyingEvidence(t *testing.T) {
	scorer := NewScorer(core.DefaultConfig())
	evidence := []core.Evidence{
		&core.OOBCallbackEvidence{
			Callback: &core.OOBCallback{
				IsResearcher: true,
			},
			Verified: false,
		},
	}

	score, confidence := scorer.CalculateConfidence(evidence)
	if score != 0 || confidence != core.ConfidenceNone {
		t.Fatalf("expected disqualified confidence, got score=%d confidence=%s", score, confidence)
	}
}
