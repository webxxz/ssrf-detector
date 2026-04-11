package detection

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ssrf-detector/internal/ai"
	"ssrf-detector/internal/core"
	"ssrf-detector/internal/payloads"
)

// FetchAnalysisEngine characterizes how the application fetches URLs
type FetchAnalysisEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

const maxWAFResponseSnippetLength = 500

// 12 is a cap for one pass: feedback-loop strategy can trigger at 10 failures,
// leaving room for up to two additional attempts in the same execution cycle.
const maxContextAwarePayloadTests = 12

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

	// Step 5: Context-aware payload generation
	envCtx := e.buildEnvironmentContext(state)
	dynamicPayloads := payloads.GeneratePayloads(envCtx)
	result.Metadata["dynamic_payload_count"] = len(dynamicPayloads)
	if len(dynamicPayloads) > 0 {
		observations, session := e.executeContextAwarePayloads(ctx, target, dynamicPayloads)
		result.Metadata["dynamic_payload_observations"] = observations
		if session != nil {
			result.Metadata["payload_attempts"] = len(session.Attempts)
			result.Metadata["payload_failures"] = len(session.Failures)
			if adjustment := ai.AnalyzeSession(session); adjustment != nil {
				result.Metadata["adaptive_strategy"] = adjustment.Strategy
				if len(adjustment.PayloadHints) > 0 {
					adaptive := make([]payloads.Payload, 0, len(adjustment.PayloadHints))
					for i, hint := range adjustment.PayloadHints {
						adaptive = append(adaptive, payloads.Payload{
							Name:     fmt.Sprintf("feedback-hint-%d", i+1),
							Category: "ai_feedback",
							Value:    hint,
						})
					}
					adaptiveObs, _ := e.executeContextAwarePayloads(ctx, target, adaptive)
					mergeObservations(observations, adaptiveObs)
					result.Metadata["dynamic_payload_observations"] = observations
				}
			}
		}

		if envCtx.WAFDetected && allObservationsFailed(observations) {
			envCtx.InitialPayloadsFailed = true
			if len(dynamicPayloads) > 0 {
				envCtx.LastBlockedPayload = dynamicPayloads[0].Value
			}
			if session != nil && len(session.WAFResponses) > 0 {
				last := session.WAFResponses[len(session.WAFResponses)-1]
				envCtx.LastWAFResponse = fmt.Sprintf("status=%d body=%s", last.StatusCode, last.BodySnippet)
			}

			mutatedQueue := payloads.GeneratePayloads(envCtx)
			aiMutated := filterAIPayloads(mutatedQueue)
			if len(aiMutated) > 0 {
				result.Metadata["ai_mutation_payload_count"] = len(aiMutated)
				adaptiveObs, _ := e.executeContextAwarePayloads(ctx, target, aiMutated)
				mergeObservations(observations, adaptiveObs)
				result.Metadata["dynamic_payload_observations"] = observations
			}
		}
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

	testTarget, err := applyInjectionPayload(target, testURL)
	if err != nil {
		return false
	}

	req, err := buildRequestFromTarget(testTarget)
	if err != nil {
		return false
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

		if _, err := e.sendTestRequest(ctx, target, testURL); err != nil {
			ports[fmt.Sprintf("port_%d", port)] = false
			continue
		}

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
	if _, err := e.sendTestRequest(ctx, target, oobURL); err != nil {
		return nil, err
	}

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
	testTarget, err := applyInjectionPayload(target, testURL)
	if err != nil {
		return nil, err
	}

	req, err := buildRequestFromTarget(testTarget)
	if err != nil {
		return nil, err
	}

	return e.httpClient.Do(ctx, req)
}

func (e *FetchAnalysisEngine) sendTestRequestWithTiming(ctx context.Context, target *core.Target, testURL string) (*core.Response, *core.RequestTiming, error) {
	testTarget, err := applyInjectionPayload(target, testURL)
	if err != nil {
		return nil, nil, err
	}

	req, err := buildRequestFromTarget(testTarget)
	if err != nil {
		return nil, nil, err
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

func (e *FetchAnalysisEngine) buildEnvironmentContext(state *core.ScanState) *payloads.EnvironmentContext {
	ctx := &payloads.EnvironmentContext{
		CloudProvider: "none",
	}

	if fpRaw, ok := state.Metadata["context_fingerprint"].(map[string]interface{}); ok {
		if backendHints, ok := fpRaw["backend_hints"].([]string); ok && len(backendHints) > 0 {
			ctx.BackendLang = backendHints[0]
		}
		if edgeHints, ok := fpRaw["edge_hints"].(map[string]bool); ok {
			ctx.WAFDetected = edgeHints["cdn_or_waf"]
			ctx.ProxyDetected = edgeHints["reverse_proxy"]
			switch {
			case edgeHints["cloudflare"]:
				ctx.WAFVendor = "cloudflare"
			case edgeHints["akamai"]:
				ctx.WAFVendor = "akamai"
			}
		}
		if cloudHints, ok := fpRaw["cloud_hints"].([]string); ok && len(cloudHints) > 0 {
			ctx.CloudProvider = strings.ToLower(cloudHints[0])
		}
	}

	if state.ClientFingerprint != nil && ctx.BackendLang == "" {
		if state.ClientFingerprint.Library == "Java" {
			ctx.BackendLang = "java"
		}
	}

	return ctx
}

func (e *FetchAnalysisEngine) executeContextAwarePayloads(ctx context.Context, target *core.Target, generated []payloads.Payload) (map[string]bool, *ai.ScanSession) {
	maxTests := maxContextAwarePayloadTests
	if len(generated) < maxTests {
		maxTests = len(generated)
	}
	observation := make(map[string]bool, maxTests)
	session := &ai.ScanSession{
		SessionID: fmt.Sprintf("fetch-%d", time.Now().UnixNano()),
	}
	if target != nil && target.URL != nil {
		session.Target = target.URL.String()
	}

	for i := 0; i < maxTests; i++ {
		payload := generated[i]
		value := payload.Value

		if strings.Contains(value, "{{OOB}}") {
			identifier, err := e.oobManager.GenerateIdentifier(target, "ctx-"+payload.Name)
			if err != nil {
				continue
			}
			value = strings.ReplaceAll(value, "{{OOB}}", identifier+"."+e.config.OOBDomain)
			resp, err := e.sendTestRequest(ctx, target, value)
			if err != nil && e.config.Verbose {
				fmt.Printf("[WARN] Context-aware payload %s failed: %v\n", payload.Name, err)
			}
			callback, _ := e.oobManager.CheckCallback(identifier)
			observation[payload.Name] = callback != nil
			attempt := ai.PayloadAttempt{Payload: value, Strategy: payload.Category, TimingMs: 0}
			if callback != nil {
				attempt.Result = "success"
			} else if err != nil {
				attempt.Result = "error"
			} else {
				attempt.Result = "blocked"
			}
			if resp != nil {
				attempt.ResponseCode = resp.StatusCode
				if resp.StatusCode >= 400 {
					snippet := wafResponseSnippet(resp)
					session.WAFResponses = append(session.WAFResponses, ai.WAFResponse{StatusCode: resp.StatusCode, BodySnippet: snippet})
				}
			}
			ai.RecordAttempt(session, attempt)
			continue
		}

		resp, err := e.sendTestRequest(ctx, target, value)
		observation[payload.Name] = err == nil && resp != nil && resp.StatusCode < 500
		attempt := ai.PayloadAttempt{Payload: value, Strategy: payload.Category, TimingMs: 0}
		if err != nil {
			attempt.Result = "error"
		} else if resp != nil && resp.StatusCode < 500 {
			attempt.Result = "success"
		} else if resp != nil && resp.StatusCode >= 500 {
			attempt.Result = "server_error"
		} else {
			attempt.Result = "blocked"
		}
		if resp != nil {
			attempt.ResponseCode = resp.StatusCode
			if resp.StatusCode >= 400 {
				snippet := wafResponseSnippet(resp)
				session.WAFResponses = append(session.WAFResponses, ai.WAFResponse{StatusCode: resp.StatusCode, BodySnippet: snippet})
			}
		}
		ai.RecordAttempt(session, attempt)
	}

	return observation, session
}

func allObservationsFailed(observations map[string]bool) bool {
	if len(observations) == 0 {
		return false
	}
	for _, ok := range observations {
		if ok {
			return false
		}
	}
	return true
}

func filterAIPayloads(in []payloads.Payload) []payloads.Payload {
	out := make([]payloads.Payload, 0)
	for _, p := range in {
		if p.Category == "ai_mutation" || p.Category == "ai_feedback" {
			out = append(out, p)
		}
	}
	return out
}

func mergeObservations(base, extra map[string]bool) {
	for k, v := range extra {
		base[k] = v
	}
}

func wafResponseSnippet(resp *core.Response) string {
	if resp == nil {
		return ""
	}
	return normalizeSample(resp.BodyBytes, maxWAFResponseSnippetLength)
}
