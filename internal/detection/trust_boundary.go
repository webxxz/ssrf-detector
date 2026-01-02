package detection

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// TrustBoundaryEngine identifies what the application trusts and where validation occurs
type TrustBoundaryEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewTrustBoundaryEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *TrustBoundaryEngine {
	return &TrustBoundaryEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *TrustBoundaryEngine) Name() core.DetectionPhase {
	return core.PhaseTrustBoundary
}

func (e *TrustBoundaryEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelNone // Uses safe external testing
}

func (e *TrustBoundaryEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{core.PhaseFetchAnalysis}
}

func (e *TrustBoundaryEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Initialize validator fingerprint
	validatorFP := &core.ValidatorFingerprint{
		BlockedRanges:  make([]string, 0),
		AllowedSchemes: make([]string, 0),
		ErrorPatterns:  make([]string, 0),
	}

	// Step 1: Detect validation layer (string vs DNS vs IP)
	validationLayer, err := e.detectValidationLayer(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Validation layer detection failed: %v\n", err)
		}
	} else {
		validatorFP.ValidationLayer = validationLayer
		result.Metadata["validation_layer"] = validationLayer
	}

	// Step 2: Test DNS resolution trust
	dnsTrust, err := e.testDNSResolutionTrust(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] DNS trust test failed: %v\n", err)
		}
	} else {
		result.Metadata["dns_trust"] = dnsTrust
	}

	// Step 3: Header trust discovery
	headerTrust, err := e.discoverHeaderTrust(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Header trust discovery failed: %v\n", err)
		}
	} else {
		result.Metadata["header_trust"] = headerTrust
	}

	// Store validator fingerprint
	state.ValidatorFingerprint = validatorFP

	result.Success = true
	result.NextPhase = core.PhaseParserDifferential
	result.Duration = time.Since(startTime)

	return result, nil
}

// detectValidationLayer determines where validation occurs in the request pipeline
func (e *TrustBoundaryEngine) detectValidationLayer(ctx context.Context, target *core.Target, state *core.ScanState) (core.ValidationLayer, error) {
	// Test 1: String-based validation detection
	// Send invalid URL format that wouldn't parse
	_, _ = e.oobManager.GenerateIdentifier(target, "validation-string")
	invalidURL := "not-a-valid-url-at-all-xyz123"

	resp1, timing1, _ := e.sendTestWithTiming(ctx, target, invalidURL)

	// If rejected immediately (< 50ms), likely string-based
	if timing1 != nil {
		responseTime := timing1.End.Sub(timing1.Start)
		if responseTime < 50*time.Millisecond && resp1 != nil && resp1.StatusCode >= 400 {
			return core.ValidationString, nil
		}
	}

	// Test 2: DNS-based validation detection
	// Send valid URL format to non-existent domain
	identifier2, _ := e.oobManager.GenerateIdentifier(target, "validation-dns")
	nonexistentURL := fmt.Sprintf("http://nonexistent-domain-%s.invalid/test", identifier2)

	resp2, timing2, _ := e.sendTestWithTiming(ctx, target, nonexistentURL)

	if timing2 != nil {
		responseTime := timing2.End.Sub(timing2.Start)

		// If response takes 1-10 seconds (DNS timeout), validation happens at DNS layer
		if responseTime > 1*time.Second && responseTime < 10*time.Second {
			// Check for DNS error in response
			if resp2 != nil && resp2.BodyBytes != nil {
				body := string(resp2.BodyBytes)
				if contains(body, "DNS") || contains(body, "resolve") || contains(body, "not found") {
					return core.ValidationDNS, nil
				}
			}
		}
	}

	// Test 3: IP-based validation detection
	// Use scanner domain that resolves to known IP
	identifier3, _ := e.oobManager.GenerateIdentifier(target, "validation-ip")
	oobURL, _ := e.oobManager.BuildURL(identifier3, "/validation-test")

	_, timing3, _ := e.sendTestWithTiming(ctx, target, oobURL)

	// Wait for callback
	oobCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	callback, _ := e.oobManager.WaitForCallback(oobCtx, identifier3, 3*time.Second)

	if callback != nil && timing3 != nil {
		// Callback received - check when validation happened
		callbackDelay := callback.Timestamp.Sub(timing3.Start)

		if callbackDelay > 100*time.Millisecond {
			// Validation happened after DNS resolution (IP-based)
			return core.ValidationIP, nil
		}
	}

	// Default: assume string-based (most restrictive)
	return core.ValidationString, nil
}

// testDNSResolutionTrust checks if application trusts DNS resolution
func (e *TrustBoundaryEngine) testDNSResolutionTrust(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]interface{}, error) {
	trust := make(map[string]interface{})

	// Test: Domain-based validation only (vulnerable to DNS rebinding)
	identifier, _ := e.oobManager.GenerateIdentifier(target, "dns-trust")
	oobURL, _ := e.oobManager.BuildURL(identifier, "/dns-trust-test")

	// First request
	_, timing1, _ := e.sendTestWithTiming(ctx, target, oobURL)

	// Check for OOB callback
	oobCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	callback, _ := e.oobManager.WaitForCallback(oobCtx, identifier, 5*time.Second)

	if callback != nil {
		// DNS was resolved and request was made
		trust["dns_resolved"] = true

		// Check timing to infer validation point
		if timing1 != nil {
			dnsTime := callback.Timestamp.Sub(timing1.Start)
			trust["dns_resolution_time_ms"] = dnsTime.Milliseconds()

			// If DNS happened quickly, validator likely doesn't re-resolve
			if dnsTime < 200*time.Millisecond {
				trust["vulnerable_to_dns_rebinding"] = true
			}
		}
	} else {
		trust["dns_resolved"] = false
	}

	return trust, nil
}

// discoverHeaderTrust tests header injection and trust
func (e *TrustBoundaryEngine) discoverHeaderTrust(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]bool, error) {
	headerTrust := make(map[string]bool)

	// Test common headers that might influence backend requests
	headersToTest := []string{
		"Host",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Real-IP",
		"Referer",
		"Origin",
	}

	for _, headerName := range headersToTest {
		trusted := e.testHeaderTrust(ctx, target, headerName, state)
		headerTrust[headerName] = trusted

		// Small delay between tests
		time.Sleep(200 * time.Millisecond)
	}

	return headerTrust, nil
}

// testHeaderTrust tests if a specific header is trusted
func (e *TrustBoundaryEngine) testHeaderTrust(ctx context.Context, target *core.Target, headerName string, state *core.ScanState) bool {
	identifier, _ := e.oobManager.GenerateIdentifier(target, fmt.Sprintf("header-%s", headerName))
	oobDomain := fmt.Sprintf("%s.%s", identifier, e.config.OOBDomain)

	// Build request with header containing OOB domain
	testTarget := *target
	testTarget.Headers = target.Headers.Clone()
	testTarget.Headers.Set(headerName, oobDomain)

	req, err := http.NewRequest(target.Method, target.URL.String(), nil)
	if err != nil {
		return false
	}

	for k, v := range testTarget.Headers {
		req.Header[k] = v
	}

	// Send request
	e.httpClient.Do(ctx, req)

	// Check for OOB callback
	oobCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	callback, err := e.oobManager.WaitForCallback(oobCtx, identifier, 3*time.Second)

	// If callback received, header value was used in backend request
	return callback != nil
}

// Helper: send test request with timing
func (e *TrustBoundaryEngine) sendTestWithTiming(ctx context.Context, target *core.Target, testURL string) (*core.Response, *core.RequestTiming, error) {
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
