package detection

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// VerificationEngine performs final verification and false positive elimination
type VerificationEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewVerificationEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *VerificationEngine {
	return &VerificationEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *VerificationEngine) Name() core.DetectionPhase {
	return core.PhaseVerification
}

func (e *VerificationEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelNone
}

func (e *VerificationEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{
		core.PhaseCapability,
	}
}

func (e *VerificationEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Step 1: Verify all OOB callbacks
	verifiedCallbacks := e.verifyOOBCallbacks(state)
	result.Metadata["verified_callbacks"] = verifiedCallbacks

	// Step 2: Check for reflection-only patterns
	isReflection := e.detectReflectionOnly(ctx, target, state)
	if isReflection {
		// Add disqualifying evidence
		evidence := &core.ReflectionOnlyEvidence{
			InputURL:      "test-url",
			NoOOBCallback: true,
			NoTimingDiff:  true,
		}
		result.Evidence = append(result.Evidence, evidence)
		state.Evidence = append(state.Evidence, evidence)
	}

	// Step 3: Statistical timing validation
	timingValid := e.validateTimingEvidence(state)
	result.Metadata["timing_valid"] = timingValid

	// Step 4: Reproducibility check
	reproducible, err := e.testReproducibility(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Reproducibility test failed: %v\n", err)
		}
	} else {
		result.Metadata["reproducible"] = reproducible

		if !reproducible {
			// Penalize confidence
			result.Metadata["reproducibility_warning"] = "Finding not consistently reproducible"
		}
	}

	result.Success = true
	result.Duration = time.Since(startTime)

	return result, nil
}

// verifyOOBCallbacks validates all OOB callbacks
func (e *VerificationEngine) verifyOOBCallbacks(state *core.ScanState) int {
	verified := 0

	for _, evidence := range state.Evidence {
		if oobEvidence, ok := evidence.(*core.OOBCallbackEvidence); ok {
			// Check source attribution
			if oobEvidence.Callback.IsTargetInfrastructure {
				verified++
			} else if !oobEvidence.Callback.IsResearcher && !oobEvidence.Callback.IsCDN {
				// Ambiguous source - needs manual review
				if e.config.Verbose {
					fmt.Printf("[WARN] OOB callback from ambiguous source: %s\n",
						oobEvidence.Callback.SourceIP)
				}
			}
		}
	}

	return verified
}

// detectReflectionOnly checks if this is just reflection without execution
func (e *VerificationEngine) detectReflectionOnly(ctx context.Context, target *core.Target, state *core.ScanState) bool {
	// Check evidence for OOB callbacks
	hasOOB := false
	hasTimingAnomaly := false
	hasInternalAccess := false

	for _, evidence := range state.Evidence {
		switch evidence.Type() {
		case core.EvidenceOOBCallback:
			if !evidence.IsDisqualifying() {
				hasOOB = true
			}
		case core.EvidenceTimingAnomaly:
			hasTimingAnomaly = true
		case core.EvidenceInternalAccess, core.EvidenceCloudMetadata:
			hasInternalAccess = true
		}
	}

	// If we have strong evidence, not reflection
	if hasOOB || hasInternalAccess {
		return false
	}

	// If only timing evidence, could be reflection
	if hasTimingAnomaly && !hasOOB && !hasInternalAccess {
		// Ambiguous - needs further testing
		return false
	}

	// No evidence of execution
	if !hasOOB && !hasTimingAnomaly && !hasInternalAccess {
		return true
	}

	return false
}

// validateTimingEvidence checks statistical validity of timing evidence
func (e *VerificationEngine) validateTimingEvidence(state *core.ScanState) bool {
	for _, evidence := range state.Evidence {
		if timingEvidence, ok := evidence.(*core.TimingAnomalyEvidence); ok {
			// Check sample size
			if timingEvidence.Samples < e.config.BaselineSamples {
				return false
			}

			// Check statistical significance
			if math.Abs(timingEvidence.ZScore) < e.config.StatisticalThreshold {
				return false
			}
		}
	}

	return true
}

// testReproducibility verifies the finding can be reproduced
func (e *VerificationEngine) testReproducibility(ctx context.Context, target *core.Target, state *core.ScanState) (bool, error) {
	// Find the test that produced strongest evidence
	strongestTest := e.findStrongestTest(state)
	if strongestTest == "" {
		return false, fmt.Errorf("no successful test found to reproduce")
	}

	// Attempt to reproduce 3 times
	successes := 0
	attempts := 3

	for i := 0; i < attempts; i++ {
		identifier, _ := e.oobManager.GenerateIdentifier(target, fmt.Sprintf("repro-%d", i))
		oobURL, _ := e.oobManager.BuildURL(identifier, "/reproducibility-test")

		// Send test
		testTarget := *target
		targetURL := *target.URL
		q := targetURL.Query()
		q.Set(target.InjectionPoint.Name, oobURL)
		targetURL.RawQuery = q.Encode()
		testTarget.URL = &targetURL

		req, err := http.NewRequest(target.Method, testTarget.URL.String(), nil)
		if err != nil {
			continue
		}

		for k, v := range target.Headers {
			req.Header[k] = v
		}

		_, err = e.httpClient.Do(ctx, req)
		if err != nil {
			continue
		}

		// Wait for callback
		oobCtx, cancel := context.WithTimeout(ctx, e.config.OOBTimeout)
		callback, err := e.oobManager.WaitForCallback(oobCtx, identifier, e.config.OOBTimeout)
		cancel()

		if err == nil && callback != nil {
			successes++
		}

		// Small delay between attempts
		time.Sleep(1 * time.Second)
	}

	// Require at least 2/3 success rate
	return successes >= 2, nil
}

// findStrongestTest identifies the test that produced best evidence
func (e *VerificationEngine) findStrongestTest(state *core.ScanState) string {
	// Look for phases that produced strong evidence
	for _, phase := range []core.DetectionPhase{
		core.PhaseInternalAccess,
		core.PhaseFetchAnalysis,
		core.PhaseCapability,
	} {
		if result, exists := state.PhaseResults[phase]; exists && result.Success {
			if len(result.Evidence) > 0 {
				return string(phase)
			}
		}
	}

	return ""
}
