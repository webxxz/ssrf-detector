package detection

import (
	"math"
	"time"

	"ssrf-detector/internal/core"
)

// OOBResult captures out-of-band callback status for fusion.
type OOBResult struct {
	Received bool
}

// PortScanResult captures inferred port-oracle behavior differences.
type PortScanResult struct {
	BehaviorDiffers bool
}

// BlindSSRFSignals contains all signals used for blind SSRF fusion scoring.
type BlindSSRFSignals struct {
	OOBCallback *OOBResult
	TimingDelta float64
	PortOracle  *PortScanResult
	ErrorDiff   float64
	SizeDelta   int
}

// FusionConfidenceLevel represents fusion classification.
type FusionConfidenceLevel string

const (
	FusionNoise     FusionConfidenceLevel = "NOISE"
	FusionMedium    FusionConfidenceLevel = "MEDIUM"
	FusionHigh      FusionConfidenceLevel = "HIGH"
	FusionConfirmed FusionConfidenceLevel = "CONFIRMED"
)

// ConfidenceScore carries fusion score and classification.
type ConfidenceScore struct {
	Score float64
	Level FusionConfidenceLevel
}

const (
	oobSignalWeight       = 0.50
	timingSignalWeight    = 0.20
	portOracleWeight      = 0.15
	errorDiffWeight       = 0.10
	sizeDeltaWeight       = 0.05
	timingDeltaThreshold  = 2 * time.Second
	errorDiffThreshold    = 0.4
	sizeDeltaThresholdAbs = 200
)

// FuseBlindSignals combines multiple blind SSRF signals into one confidence score.
func FuseBlindSignals(signals *BlindSSRFSignals) ConfidenceScore {
	if signals == nil {
		return ConfidenceScore{Score: 0, Level: FusionNoise}
	}

	score := 0.0

	if signals.OOBCallback != nil && signals.OOBCallback.Received {
		score += oobSignalWeight
	}
	if signals.TimingDelta > float64(timingDeltaThreshold.Milliseconds()) {
		score += timingSignalWeight
	}
	if signals.PortOracle != nil && signals.PortOracle.BehaviorDiffers {
		score += portOracleWeight
	}
	if signals.ErrorDiff > errorDiffThreshold {
		score += errorDiffWeight
	}
	if math.Abs(float64(signals.SizeDelta)) > sizeDeltaThresholdAbs {
		score += sizeDeltaWeight
	}

	if score > 1 {
		score = 1
	}

	return ConfidenceScore{
		Score: score,
		Level: classifyScore(score),
	}
}

// BuildBlindSignals extracts fusion-ready signals from scan state.
func BuildBlindSignals(state *core.ScanState) *BlindSSRFSignals {
	signals := &BlindSSRFSignals{
		OOBCallback: &OOBResult{Received: false},
		TimingDelta: 0,
		PortOracle:  &PortScanResult{BehaviorDiffers: false},
		ErrorDiff:   0,
		SizeDelta:   0,
	}
	if state == nil {
		return signals
	}

	for _, ev := range state.Evidence {
		switch typed := ev.(type) {
		case *core.OOBCallbackEvidence:
			if typed.Callback != nil && !typed.Callback.IsResearcher {
				signals.OOBCallback.Received = true
			}
		case *core.TimingAnomalyEvidence:
			if typed.BaselineMean > 0 {
				diffMS := math.Abs(float64((typed.TestDuration - typed.BaselineMean).Milliseconds()))
				if diffMS > signals.TimingDelta {
					signals.TimingDelta = diffMS
				}
			}
		}
	}

	if result, exists := state.PhaseResults[core.PhaseFetchAnalysis]; exists && result != nil {
		if portsRaw, ok := result.Metadata["port_restrictions"].(map[string]bool); ok {
			allowed := 0
			blocked := 0
			for _, isAllowed := range portsRaw {
				if isAllowed {
					allowed++
				} else {
					blocked++
				}
			}
			signals.PortOracle.BehaviorDiffers = allowed > 0 && blocked > 0
		}
	}

	if profileRaw, ok := state.Metadata["baseline_profile"]; ok {
		if profile, ok := profileRaw.(*BaselineProfile); ok && profile != nil {
			probe := &ProbeResult{
				StatusCode:   profile.StatusCode,
				ResponseSize: profile.ResponseSize,
				ResponseTime: profile.ResponseTime,
			}

			if reach, exists := state.PhaseResults[core.PhaseReachability]; exists && reach != nil {
				if ep, ok := reach.Metadata["error_pattern"].(string); ok {
					probe.ErrorPattern = ep
				}
			}

			signals.ErrorDiff = DiffFromBaseline(profile, probe)
			signals.SizeDelta = probe.ResponseSize - profile.ResponseSize
		}
	}

	return signals
}

func classifyScore(score float64) FusionConfidenceLevel {
	switch {
	case score >= 0.95:
		return FusionConfirmed
	case score >= 0.75:
		return FusionHigh
	case score >= 0.50:
		return FusionMedium
	default:
		return FusionNoise
	}
}
