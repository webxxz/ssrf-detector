package detection

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// FetchAnalysisEngine characterizes how the application fetches URLs
type FetchAnalysisEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewFetchAnalysisEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *FetchAnalysisEngine {
	return &FetchAnalysisEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *FetchAnalysisEngine) Name() core.DetectionPhase {
	return core.PhaseFetchAnalysis
}

func (e *FetchAnalysisEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelNone
}

func (e *FetchAnalysisEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{core.PhaseCapability}
}

func (e *FetchAnalysisEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Only run if server-side fetch capability detected
	if !state.Capabilities["server_side_fetch"] {
		result.Success = false
		result.ShouldStop = true
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Step 1: Protocol support discovery
	protocols, err := e.discoverProtocolSupport(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Protocol discovery failed: %v\n", err)
		}
	} else {
		result.Metadata["supported_protocols"] = protocols
	}

	// Step 2: Hostname validation mapping
	validation, err := e.mapHostnameValidation(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Hostname validation mapping failed: %v\n", err)
		}
	} else {
		result.Metadata["hostname_validation"] = validation
	}

	// Step 3: Port restriction discovery
	ports, err := e.discoverPortRestrictions(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Port restriction discovery failed: %v\n", err)
		}
	} else {
		result.Metadata["port_restrictions"] = ports
	}

	// Step 4: Client fingerprinting
	fingerprint, err := e.fingerprintHTTPClient(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Client fingerprinting failed: %v\n", err)
		}
	} else {
		state.ClientFingerprint = fingerprint
		result.Metadata["client_fingerprint"] = fingerprint
	}

	result.Success = true
	result.NextPhase = core.PhaseTrustBoundary
	result.Duration = time.Since(startTime)

	return result, nil
}

// discoverProtocolSupport tests which URL schemes are supported
func (e *FetchAnalysisEngine) discoverProtocolSupport(ctx context.Context, target *core.Target, state *core.ScanState) ([]string, error) {
	supported := make([]string, 0)

	// Test http (baseline)
	if e.testProtocol(ctx, target, "http", state) {
		supported = append(supported, "http")
	}

	// Test https
	if e.testProtocol(ctx, target, "https", state) {
		supported = append(supported, "https")
	}

	// Test case sensitivity
	if e.testProtocol(ctx, target, "HTTP", state) {
		supported = append(supported, "HTTP (case-insensitive)")
	}

	return supported, nil
}

// testProtocol tests if a specific protocol is supported
func (e *FetchAnalysisEngine) testProtocol(ctx context.Context, target *core.Target, scheme string, state *core.ScanState) bool {
	identifier, err := e.oobManager.GenerateIdentifier(target, fmt.Sprintf("protocol-%s", scheme))
	if err != nil {
		return false
	}

	oobURL, err := e.oobManager.BuildURL(identifier, fmt.Sprintf("/protocol-%s", scheme))
	if err != nil {
		return false
	}

	// Replace scheme
	testURL := oobURL
	if scheme != "http" {
		testURL = scheme + oobURL[4:] // Replace "http" with scheme
	}

	// Send request
	testTarget := *target
	targetURL := *target.URL
	q := targetURL.Query()
	q.Set(target.InjectionPoint.Name, testURL)
	targetURL.RawQuery = q.Encode()
	testTarget.URL = &targetURL

	req, err := http.NewRequest(target.Method, testTarget.URL.String(), nil)
	if err != nil {
		return false
	}

	for k, v := range target.Headers {
		req.Header[k] = v
	}

	_, err = e.httpClient.Do(ctx, req)
	if err != nil {
		return false
	}

	// Check for callback
	callback, found := e.oobManager.CheckCallback(identifier)
	return found && callback != nil
}

// mapHostnameValidation discovers hostname validation behavior
func (e *FetchAnalysisEngine) mapHostnameValidation(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]interface{}, error) {
	validation := make(map[string]interface{})

	// Test with scanner domain (should be allowed)
	identifier1, _ := e.oobManager.GenerateIdentifier(target, "hostname-valid")
	oobURL1, _ := e.oobManager.BuildURL(identifier1, "/valid")

	_, _ = e.sendTestRequest(ctx, target, oobURL1)
	callback1, _ := e.oobManager.CheckCallback(identifier1)

	validation["scanner_domain_allowed"] = (callback1 != nil)

	// Test with non-existent domain
	identifier2, _ := e.oobManager.GenerateIdentifier(target, "hostname-nonexist")
	nonExistURL := fmt.Sprintf("http://nonexistent-domain-xyz-%s.invalid/test", identifier2)

	resp2, timing2, _ := e.sendTestRequestWithTiming(ctx, target, nonExistURL)

	// Analyze timing
	if timing2 != nil && state.Baseline != nil {
		delay := timing2.End.Sub(timing2.Start)
		if delay > 5*time.Second {
			validation["dns_resolution_attempted"] = true
		} else {
			validation["dns_resolution_attempted"] = false
		}
	}

	// Check error messages
	if resp2 != nil && resp2.BodyBytes != nil {
		body := string(resp2.BodyBytes)
		if contains(body, "DNS") || contains(body, "resolution failed") {
			validation["dns_errors_revealed"] = true
		}
	}

	return validation, nil
}

// discoverPortRestrictions tests port accessibility
func (e *FetchAnalysisEngine) discoverPortRestrictions(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]bool, error) {
	ports := make(map[string]bool)

	testPorts := []int{80, 443, 8080, 22, 3306, 6379}

	for _, port := range testPorts {
		identifier, _ := e.oobManager.GenerateIdentifier(target, fmt.Sprintf("port-%d", port))
		_, _ = e.oobManager.BuildURL(identifier, fmt.Sprintf("/port-%d", port))

		// Add port to URL
		testURL := fmt.Sprintf("http://%s.%s:%d/test", identifier, e.config.OOBDomain, port)

		e.sendTestRequest(ctx, target, testURL)

		callback, _ := e.oobManager.CheckCallback(identifier)
		ports[fmt.Sprintf("port_%d", port)] = (callback != nil)

		// Small delay between tests
		time.Sleep(200 * time.Millisecond)
	}

	return ports, nil
}

// fingerprintHTTPClient identifies the HTTP client library
func (e *FetchAnalysisEngine) fingerprintHTTPClient(ctx context.Context, target *core.Target, state *core.ScanState) (*core.HTTPClientFingerprint, error) {
	// Generate OOB identifier
	identifier, err := e.oobManager.GenerateIdentifier(target, "fingerprint")
	if err != nil {
		return nil, err
	}

	oobURL, err := e.oobManager.BuildURL(identifier, "/fingerprint")
	if err != nil {
		return nil, err
	}

	// Send request
	e.sendTestRequest(ctx, target, oobURL)

	// Wait for callback
	oobCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	callback, err := e.oobManager.WaitForCallback(oobCtx, identifier, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// Build fingerprint from callback
	fingerprint := &core.HTTPClientFingerprint{
		UserAgent: callback.UserAgent,
		Headers:   callback.Headers,
	}

	// Identify library from User-Agent
	if callback.UserAgent != "" {
		fingerprint.Library, fingerprint.Version = parseUserAgent(callback.UserAgent)
	}

	// Infer protocol support based on library
	fingerprint.ProtocolSupport = inferProtocolSupport(fingerprint.Library)

	return fingerprint, nil
}

// Helper functions

func (e *FetchAnalysisEngine) sendTestRequest(ctx context.Context, target *core.Target, testURL string) (*core.Response, error) {
	testTarget := *target
	targetURL := *target.URL

	q := targetURL.Query()
	q.Set(target.InjectionPoint.Name, testURL)
	targetURL.RawQuery = q.Encode()
	testTarget.URL = &targetURL

	req, err := http.NewRequest(target.Method, testTarget.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	for k, v := range target.Headers {
		req.Header[k] = v
	}

	return e.httpClient.Do(ctx, req)
}

func (e *FetchAnalysisEngine) sendTestRequestWithTiming(ctx context.Context, target *core.Target, testURL string) (*core.Response, *core.RequestTiming, error) {
	testTarget := *target
	targetURL := *target.URL

	q := targetURL.Query()
	q.Set(target.InjectionPoint.Name, testURL)
	targetURL.RawQuery = q.Encode()
	testTarget.URL = &targetURL

	req, err := http.NewRequest(target.Method, testTarget.URL.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	for k, v := range target.Headers {
		req.Header[k] = v
	}

	return e.httpClient.DoWithTiming(ctx, req)
}

func parseUserAgent(ua string) (library string, version string) {
	// Simple parsing - in production use regex
	if contains(ua, "Python-urllib") {
		return "Python-urllib", extractVersion(ua, "Python-urllib/")
	}
	if contains(ua, "curl") {
		return "curl", extractVersion(ua, "curl/")
	}
	if contains(ua, "Go-http-client") {
		return "Go-http-client", extractVersion(ua, "Go-http-client/")
	}
	if contains(ua, "Java") {
		return "Java", extractVersion(ua, "Java/")
	}

	return "Unknown", ""
}

func extractVersion(ua string, prefix string) string {
	// Simple version extraction
	if !contains(ua, prefix) {
		return ""
	}

	// Find version after prefix
	// This is simplified - use proper parsing in production
	return "1.0"
}

func inferProtocolSupport(library string) []string {
	switch library {
	case "Python-urllib":
		return []string{"http", "https", "ftp", "file"}
	case "curl":
		return []string{"http", "https", "ftp", "ftps", "gopher", "dict", "file", "ldap"}
	case "Go-http-client":
		return []string{"http", "https"}
	case "Java":
		return []string{"http", "https", "ftp", "file"}
	default:
		return []string{"http", "https"}
	}
}
