package detection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
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

	// Step 1b: Contextual fingerprinting (stack/edge/cloud hints)
	fingerprint, err := e.collectContextFingerprint(ctx, target)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Context fingerprinting failed: %v\n", err)
		}
	} else {
		result.Metadata["context_fingerprint"] = fingerprint
		state.Metadata["context_fingerprint"] = fingerprint
	}

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
	req, err := buildRequestFromTarget(target)
	if err != nil {
		return nil, err
	}

	// Apply modifications if any
	// if modifications != nil {
	// 	for k, v := range modifications {
	// 		req.Header.Set(k, v)
	// 	}
	// }

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
	errorTarget, err := applyInjectionPayload(target, "::INVALID_URL::")
	if err != nil {
		// Keep baseline behavior even if this injection type is unsupported.
		return cloneTarget(target)
	}
	return errorTarget
}

func (e *ReachabilityEngine) collectContextFingerprint(ctx context.Context, target *core.Target) (map[string]interface{}, error) {
	req, err := e.buildRequest(target, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.httpClient.Do(ctx, req)
	if err != nil {
		return nil, err
	}

	fingerprint := map[string]interface{}{
		"backend_hints": inferBackendHints(resp),
		"edge_hints":    inferEdgeHints(resp),
		"cloud_hints":   inferCloudHints(resp),
	}
	return fingerprint, nil
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

func inferBackendHints(resp *core.Response) []string {
	if resp == nil {
		return nil
	}

	hints := make([]string, 0)
	cookies := strings.ToLower(strings.Join(resp.Header.Values("Set-Cookie"), ";"))
	server := strings.ToLower(resp.Header.Get("Server"))
	body := normalizeSample(resp.BodyBytes, 4096)

	if strings.Contains(cookies, "jsessionid") || strings.Contains(server, "tomcat") {
		hints = append(hints, "java")
	}
	if strings.Contains(cookies, "phpsessid") || strings.Contains(server, "php") {
		hints = append(hints, "php")
	}
	if strings.Contains(cookies, "asp.net_sessionid") || strings.Contains(server, "asp.net") {
		hints = append(hints, "dotnet")
	}
	if strings.Contains(server, "express") || strings.Contains(body, "express") {
		hints = append(hints, "nodejs")
	}
	if strings.Contains(server, "gunicorn") || strings.Contains(server, "uwsgi") {
		hints = append(hints, "python")
	}

	return dedupeStrings(hints)
}

func inferEdgeHints(resp *core.Response) map[string]bool {
	edge := map[string]bool{
		"reverse_proxy": false,
		"cdn_or_waf":    false,
		"cloudflare":    false,
		"akamai":        false,
		"fastly":        false,
	}
	if resp == nil {
		return edge
	}

	server := strings.ToLower(resp.Header.Get("Server"))
	via := strings.ToLower(resp.Header.Get("Via"))
	xcache := strings.ToLower(resp.Header.Get("X-Cache"))
	poweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

	if via != "" || xcache != "" || strings.Contains(server, "nginx") || strings.Contains(server, "envoy") {
		edge["reverse_proxy"] = true
	}
	if strings.Contains(server, "cloudflare") || strings.Contains(via, "cloudflare") {
		edge["cdn_or_waf"] = true
		edge["cloudflare"] = true
	}
	if strings.Contains(server, "akamai") || strings.Contains(via, "akamai") {
		edge["cdn_or_waf"] = true
		edge["akamai"] = true
	}
	if strings.Contains(server, "fastly") || strings.Contains(via, "fastly") || strings.Contains(poweredBy, "fastly") {
		edge["cdn_or_waf"] = true
		edge["fastly"] = true
	}

	return edge
}

func inferCloudHints(resp *core.Response) []string {
	if resp == nil {
		return nil
	}

	hints := make([]string, 0)
	joined := strings.ToLower(resp.Header.Get("Server") + " " + strings.Join(resp.Header.Values("Set-Cookie"), " ") + " " + normalizeSample(resp.BodyBytes, 4096))

	if strings.Contains(joined, "x-amz") || strings.Contains(joined, "amazon") || strings.Contains(joined, "aws") {
		hints = append(hints, "aws")
	}
	if strings.Contains(joined, "x-goog") || strings.Contains(joined, "gcp") || strings.Contains(joined, "google cloud") {
		hints = append(hints, "gcp")
	}
	if strings.Contains(joined, "x-ms") || strings.Contains(joined, "azure") || strings.Contains(joined, "microsoft") {
		hints = append(hints, "azure")
	}

	return dedupeStrings(hints)
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

func normalizeSample(body []byte, max int) string {
	if len(body) == 0 {
		return ""
	}
	if max > 0 && len(body) > max {
		body = body[:max]
	}
	return strings.ToLower(string(body))
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
