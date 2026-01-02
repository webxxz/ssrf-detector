package detection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// ReachabilityEngine tests basic connectivity and establishes baseline
type ReachabilityEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
}

// NewReachabilityEngine creates a new reachability engine
func NewReachabilityEngine(config *core.Config, httpClient core.HTTPClient) *ReachabilityEngine {
	return &ReachabilityEngine{
		config:     config,
		httpClient: httpClient,
	}
}

func (e *ReachabilityEngine) Name() core.DetectionPhase {
	return core.PhaseReachability
}

func (e *ReachabilityEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelNone
}

func (e *ReachabilityEngine) DependsOn() []core.DetectionPhase {
	return nil // No dependencies
}

// Execute performs reachability testing
func (e *ReachabilityEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Step 1: Baseline request (normal parameter value)
	baseline, err := e.performBaselineRequest(ctx, target)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(startTime)
		return result, nil
	}

	state.Baseline = baseline
	result.Metadata["baseline"] = baseline

	// Step 2: Canary request (benign, non-existent parameter)
	canaryResp, err := e.performCanaryRequest(ctx, target)
	if err != nil {
		// Canary failure is not critical
		if e.config.Verbose {
			fmt.Printf("[WARN] Canary request failed: %v\n", err)
		}
	} else {
		// Check if application processes arbitrary parameters
		if canaryResp.StatusCode == baseline.StatusCode {
			state.Capabilities["accepts_arbitrary_params"] = true
			result.Metadata["canary_accepted"] = true
		}
	}

	// Step 3: Error state request (invalid value)
	errorResp, err := e.performErrorRequest(ctx, target)
	if err == nil {
		errorPattern := e.analyzeErrorResponse(errorResp)
		if errorPattern != "" {
			result.Metadata["error_pattern"] = errorPattern

			// Create error evidence
			evidence := &ErrorMessageEvidence{
				ErrorPattern: errorPattern,
				StatusCode:   errorResp.StatusCode,
				timestamp:    time.Now(),
			}
			result.Evidence = append(result.Evidence, evidence)
		}
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	result.NextPhase = core.PhaseCapability

	return result, nil
}

// performBaselineRequest establishes normal behavior
func (e *ReachabilityEngine) performBaselineRequest(ctx context.Context, target *core.Target) (*core.Baseline, error) {
	samples := make([]time.Duration, 0, e.config.BaselineSamples)
	var lastResponse *core.Response

	// Collect multiple samples for statistical analysis
	for i := 0; i < e.config.BaselineSamples; i++ {
		req, err := e.buildRequest(target, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build request: %w", err)
		}

		startTime := time.Now()
		resp, err := e.httpClient.Do(ctx, req)
		duration := time.Since(startTime)

		if err != nil {
			return nil, fmt.Errorf("baseline request failed: %w", err)
		}

		samples = append(samples, duration)
		lastResponse = resp

		// Small delay between samples
		time.Sleep(100 * time.Millisecond)
	}

	// Calculate statistics
	mean, stdDev := calculateStats(samples)

	// Hash response body
	bodyHash := ""
	if lastResponse != nil && lastResponse.BodyBytes != nil {
		hash := sha256.Sum256(lastResponse.BodyBytes)
		bodyHash = hex.EncodeToString(hash[:])
	}

	baseline := &core.Baseline{
		ResponseTime:       mean,
		ResponseTimeStdDev: stdDev,
		ResponseSize:       len(lastResponse.BodyBytes),
		ResponseHash:       bodyHash,
		StatusCode:         lastResponse.StatusCode,
		Headers:            lastResponse.Header.Clone(),
		Samples:            e.config.BaselineSamples,
		TimingSamples:      samples,
	}

	return baseline, nil
}

// performCanaryRequest tests with benign non-existent parameter
func (e *ReachabilityEngine) performCanaryRequest(ctx context.Context, target *core.Target) (*core.Response, error) {
	// Add a canary parameter that shouldn't exist
	canaryTarget := e.addCanaryParameter(target)

	req, err := e.buildRequest(canaryTarget, nil)
	if err != nil {
		return nil, err
	}

	return e.httpClient.Do(ctx, req)
}

// performErrorRequest tests with invalid value
func (e *ReachabilityEngine) performErrorRequest(ctx context.Context, target *core.Target) (*core.Response, error) {
	// Use an invalid value for the target parameter
	errorTarget := e.setInvalidValue(target)

	req, err := e.buildRequest(errorTarget, nil)
	if err != nil {
		return nil, err
	}

	return e.httpClient.Do(ctx, req)
}

// analyzeErrorResponse extracts error patterns
func (e *ReachabilityEngine) analyzeErrorResponse(resp *core.Response) string {
	if resp == nil || resp.BodyBytes == nil {
		return ""
	}

	body := string(resp.BodyBytes)

	// Common error patterns
	patterns := []string{
		"Invalid URL",
		"Malformed URL",
		"DNS resolution failed",
		"Connection refused",
		"Connection timeout",
		"Invalid hostname",
		"Protocol not supported",
	}

	for _, pattern := range patterns {
		if contains(body, pattern) {
			return pattern
		}
	}

	return ""
}

// buildRequest constructs an HTTP request
func (e *ReachabilityEngine) buildRequest(target *core.Target, modifications map[string]string) (*http.Request, error) {
	req, err := http.NewRequest(target.Method, target.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Copy headers
	for k, v := range target.Headers {
		req.Header[k] = v
	}

	// Apply modifications if any
	if modifications != nil {
		for k, v := range modifications {
			req.Header.Set(k, v)
		}
	}

	return req, nil
}

// addCanaryParameter adds a non-existent parameter
func (e *ReachabilityEngine) addCanaryParameter(target *core.Target) *core.Target {
	canaryTarget := *target
	canaryURL := *target.URL

	q := canaryURL.Query()
	q.Set("_canary_param_xyz", "test")
	canaryURL.RawQuery = q.Encode()

	canaryTarget.URL = &canaryURL
	return &canaryTarget
}

// setInvalidValue sets an invalid value for testing
func (e *ReachabilityEngine) setInvalidValue(target *core.Target) *core.Target {
	errorTarget := *target
	errorURL := *target.URL

	q := errorURL.Query()

	// Set invalid value for the injection point
	if target.InjectionPoint.Type == core.InjectionQuery {
		q.Set(target.InjectionPoint.Name, "::INVALID_URL::")
	}

	errorURL.RawQuery = q.Encode()
	errorTarget.URL = &errorURL

	return &errorTarget
}

// Helper functions

func calculateStats(samples []time.Duration) (mean time.Duration, stdDev time.Duration) {
	if len(samples) == 0 {
		return 0, 0
	}

	// Calculate mean
	var sum time.Duration
	for _, s := range samples {
		sum += s
	}
	mean = sum / time.Duration(len(samples))

	// Calculate standard deviation
	var variance float64
	for _, s := range samples {
		diff := float64(s - mean)
		variance += diff * diff
	}
	variance /= float64(len(samples))

	stdDev = time.Duration(sqrt(variance))
	return
}

func sqrt(x float64) float64 {
	// Simple sqrt implementation
	if x == 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ErrorMessageEvidence captures error pattern evidence
type ErrorMessageEvidence struct {
	ErrorPattern string
	StatusCode   int
	timestamp    time.Time
}

func (e *ErrorMessageEvidence) Type() core.EvidenceType {
	return core.EvidenceErrorMessage
}

func (e *ErrorMessageEvidence) Score() int {
	return 10 // Minor evidence
}

func (e *ErrorMessageEvidence) Description() string {
	return fmt.Sprintf("Error pattern detected: %s (status: %d)", e.ErrorPattern, e.StatusCode)
}

func (e *ErrorMessageEvidence) Data() interface{} {
	return map[string]interface{}{
		"pattern": e.ErrorPattern,
		"status":  e.StatusCode,
	}
}

func (e *ErrorMessageEvidence) Timestamp() time.Time {
	return e.timestamp
}

func (e *ErrorMessageEvidence) IsDisqualifying() bool {
	return false
}
