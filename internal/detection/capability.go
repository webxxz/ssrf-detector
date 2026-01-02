package detection

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// CapabilityEngine discovers if endpoint has URL-fetching or redirect capabilities
type CapabilityEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewCapabilityEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *CapabilityEngine {
	return &CapabilityEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *CapabilityEngine) Name() core.DetectionPhase {
	return core.PhaseCapability
}

func (e *CapabilityEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelNone
}

func (e *CapabilityEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{core.PhaseReachability}
}

func (e *CapabilityEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Generate OOB identifier
	identifier, err := e.oobManager.GenerateIdentifier(target, "capability-test")
	if err != nil {
		return result, fmt.Errorf("failed to generate identifier: %w", err)
	}

	// Build OOB URL
	oobURL, err := e.oobManager.BuildURL(identifier, "/capability-test")
	if err != nil {
		return result, fmt.Errorf("failed to build OOB URL: %w", err)
	}

	// Test 1: Safe external fetch test
	testResp, timing, err := e.testExternalFetch(ctx, target, oobURL)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] External fetch test failed: %v\n", err)
		}
	}

	// Wait for OOB callback
	oobCtx, oobCancel := context.WithTimeout(ctx, e.config.OOBTimeout)
	defer oobCancel()

	callback, err := e.oobManager.WaitForCallback(oobCtx, identifier, e.config.OOBTimeout)

	// Analyze results
	capability := e.analyzeCapability(testResp, callback, timing, state.Baseline)

	result.Metadata["capability"] = capability
	state.Capabilities["capability_type"] = true

	// Determine next phase based on capability
	switch capability {
	case "SERVER_SIDE_FETCH":
		state.Capabilities["server_side_fetch"] = true
		result.NextPhase = core.PhaseFetchAnalysis
		result.Success = true

		if callback != nil {
			evidence := &core.OOBCallbackEvidence{
				Callback:      callback,
				CorrelationID: identifier,
				Verified:      true,
			}
			result.Evidence = append(result.Evidence, evidence)
		}

	case "REDIRECT":
		state.Capabilities["redirect"] = true
		result.NextPhase = core.PhaseRedirectAnalysis
		result.Success = true

	case "HEADER_TRUST":
		state.Capabilities["header_trust"] = true
		result.NextPhase = core.PhaseTrustBoundary
		result.Success = true

	default:
		// No capability detected
		result.Success = false
		result.ShouldStop = true
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// testExternalFetch tests if application fetches external URLs
func (e *CapabilityEngine) testExternalFetch(ctx context.Context, target *core.Target, oobURL string) (*core.Response, *core.RequestTiming, error) {
	// Build test request with OOB URL
	testTarget := *target
	testURL := *target.URL

	q := testURL.Query()
	q.Set(target.InjectionPoint.Name, oobURL)
	testURL.RawQuery = q.Encode()

	testTarget.URL = &testURL

	req, err := http.NewRequest(target.Method, testTarget.URL.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	// Copy headers
	for k, v := range target.Headers {
		req.Header[k] = v
	}

	// Execute with timing
	return e.httpClient.DoWithTiming(ctx, req)
}

// analyzeCapability determines what capability exists
func (e *CapabilityEngine) analyzeCapability(resp *core.Response, callback *core.OOBCallback, timing *core.RequestTiming, baseline *core.Baseline) string {
	// Priority 1: OOB callback received
	if callback != nil {
		// Check timing: before or after response?
		if timing != nil && callback.Timestamp.Before(timing.End) {
			// Server-side fetch (callback during request processing)
			return "SERVER_SIDE_FETCH"
		}

		// Could be async fetch or client-side
		// Check user-agent
		if callback.UserAgent != "" && !isServerLibrary(callback.UserAgent) {
			// Browser user-agent suggests client-side
			return "REDIRECT"
		}

		return "SERVER_SIDE_FETCH"
	}

	// Priority 2: Check for redirect in response
	if resp != nil {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location != "" {
				return "REDIRECT"
			}
		}

		// Check for meta refresh or JavaScript redirect
		if containsRedirectPattern(resp.BodyBytes) {
			return "REDIRECT"
		}

		// Check if response includes external content
		if len(resp.BodyBytes) > 0 {
			// Look for OOB domain in response
			if contains(string(resp.BodyBytes), e.config.OOBDomain) {
				// Could be reflection or actual fetch
				// Need more analysis in next phase
				return "POSSIBLE_FETCH"
			}
		}
	}

	// Priority 3: Timing analysis
	if timing != nil && baseline != nil {
		// Check if response was significantly slower
		if timing.End.Sub(timing.Start) > baseline.ResponseTime+3*baseline.ResponseTimeStdDev {
			// Possible server-side fetch (no callback due to network restriction)
			return "POSSIBLE_BLIND_FETCH"
		}
	}

	return "NONE"
}

// isServerLibrary checks if user-agent suggests server-side library
func isServerLibrary(userAgent string) bool {
	serverLibraries := []string{
		"Python-urllib",
		"python-requests",
		"Go-http-client",
		"Java/",
		"curl/",
		"libcurl",
		"Wget/",
		"Apache-HttpClient",
		"okhttp",
		"node-fetch",
	}

	for _, lib := range serverLibraries {
		if contains(userAgent, lib) {
			return true
		}
	}

	return false
}

// containsRedirectPattern checks for redirect indicators in response
func containsRedirectPattern(body []byte) bool {
	if body == nil {
		return false
	}

	s := string(body)

	patterns := []string{
		"window.location",
		"document.location",
		"location.href",
		"location.replace",
		"<meta http-equiv=\"refresh\"",
	}

	for _, pattern := range patterns {
		if contains(s, pattern) {
			return true
		}
	}

	return false
}
