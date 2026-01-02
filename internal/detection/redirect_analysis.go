package detection

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// RedirectAnalysisEngine analyzes redirect behavior for open redirect and redirect->SSRF
type RedirectAnalysisEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewRedirectAnalysisEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *RedirectAnalysisEngine {
	return &RedirectAnalysisEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *RedirectAnalysisEngine) Name() core.DetectionPhase {
	return core.PhaseRedirectAnalysis
}

func (e *RedirectAnalysisEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelNone
}

func (e *RedirectAnalysisEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{core.PhaseCapability}
}

func (e *RedirectAnalysisEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Only run if redirect capability detected
	if !state.Capabilities["redirect"] {
		result.Success = false
		result.ShouldStop = true
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Step 1: Identify redirect mechanism
	mechanism, err := e.identifyRedirectMechanism(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Redirect mechanism identification failed: %v\n", err)
		}
	} else {
		result.Metadata["mechanism"] = mechanism
	}

	// Step 2: Test client vs server-side redirect
	serverSide, err := e.testServerSideRedirect(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Server-side redirect test failed: %v\n", err)
		}
	} else {
		result.Metadata["server_side"] = serverSide

		if serverSide {
			state.Capabilities["server_side_redirect"] = true
		}
	}

	// Step 3: Test redirect chain following
	chainFollowing, err := e.testRedirectChainFollowing(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Redirect chain test failed: %v\n", err)
		}
	} else {
		result.Metadata["chain_following"] = chainFollowing
	}

	// Step 4: Test destination validation
	validation, err := e.testDestinationValidation(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Destination validation test failed: %v\n", err)
		}
	} else {
		result.Metadata["destination_validation"] = validation
	}

	result.Success = true
	result.NextPhase = core.PhaseVerification
	result.Duration = time.Since(startTime)

	return result, nil
}

// identifyRedirectMechanism determines how the application redirects
func (e *RedirectAnalysisEngine) identifyRedirectMechanism(ctx context.Context, target *core.Target, state *core.ScanState) (string, error) {
	identifier, _ := e.oobManager.GenerateIdentifier(target, "redirect-mechanism")
	oobURL, _ := e.oobManager.BuildURL(identifier, "/redirect-test")

	resp, err := e.sendTest(ctx, target, oobURL)
	if err != nil {
		return "", err
	}

	// Check for HTTP redirect
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			return "HTTP_3XX", nil
		}
	}

	// Check for meta refresh
	if resp.BodyBytes != nil {
		body := string(resp.BodyBytes)
		if contains(body, "meta http-equiv=\"refresh\"") {
			return "META_REFRESH", nil
		}

		// Check for JavaScript redirect
		if contains(body, "window.location") || contains(body, "location.href") {
			return "JAVASCRIPT", nil
		}
	}

	return "UNKNOWN", nil
}

// testServerSideRedirect determines if server follows redirects server-side
func (e *RedirectAnalysisEngine) testServerSideRedirect(ctx context.Context, target *core.Target, state *core.ScanState) (bool, error) {
	// Critical test: Does server fetch the redirect target before sending redirect to client?

	identifier, _ := e.oobManager.GenerateIdentifier(target, "server-redirect")
	oobURL, _ := e.oobManager.BuildURL(identifier, "/server-side-test")

	// Record request time
	requestTime := time.Now()

	// Send request
	resp, err := e.sendTest(ctx, target, oobURL)
	if err != nil {
		return false, err
	}

	responseTime := time.Now()

	// Wait for OOB callback
	oobCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	callback, err := e.oobManager.WaitForCallback(oobCtx, identifier, 5*time.Second)

	if callback == nil {
		// No callback - likely client-side redirect only
		return false, nil
	}

	// Check timing: Was callback BEFORE response (server-side) or AFTER (client-side)?
	if callback.Timestamp.Before(responseTime) {
		// Server fetched before responding to client
		return true, nil
	}

	// Check if callback came from server infrastructure
	if callback.IsTargetInfrastructure {
		// Even if after response, if from server, it's server-side (async)
		return true, nil
	}

	// Check User-Agent
	if callback.UserAgent != "" && isServerLibrary(callback.UserAgent) {
		return true, nil
	}

	return false, nil
}

// testRedirectChainFollowing tests if server follows redirect chains
func (e *RedirectAnalysisEngine) testRedirectChainFollowing(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// This requires setting up a redirect chain on the OOB server
	// For now, we'll test single redirect and infer

	identifier, _ := e.oobManager.GenerateIdentifier(target, "redirect-chain")
	oobURL, _ := e.oobManager.BuildURL(identifier, "/chain-test")

	resp, _ := e.sendTest(ctx, target, oobURL)

	// Check if redirect was followed
	if resp != nil && resp.FinalURL != "" && resp.FinalURL != resp.Request.URL.String() {
		result["follows_redirects"] = true
		result["redirect_count"] = len(resp.RedirectChain)
	} else {
		result["follows_redirects"] = false
	}

	return result, nil
}

// testDestinationValidation tests if redirect destinations are validated
func (e *RedirectAnalysisEngine) testDestinationValidation(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]interface{}, error) {
	validation := make(map[string]interface{})

	// Test 1: Same-domain redirect (should work)
	sameDomainResp, _ := e.sendTest(ctx, target, "https://"+target.URL.Host+"/redirect-test")
	validation["same_domain"] = (sameDomainResp != nil && sameDomainResp.StatusCode < 400)

	// Test 2: External domain redirect
	identifier, _ := e.oobManager.GenerateIdentifier(target, "external-redirect")
	externalURL, _ := e.oobManager.BuildURL(identifier, "/external-test")

	externalResp, _ := e.sendTest(ctx, target, externalURL)

	if externalResp != nil {
		if externalResp.StatusCode >= 300 && externalResp.StatusCode < 400 {
			location := externalResp.Header.Get("Location")
			validation["external_domain"] = (location != "")
			validation["external_allowed"] = true
		} else if externalResp.StatusCode >= 400 {
			validation["external_allowed"] = false
		} else {
			validation["external_allowed"] = true
		}
	}

	// Test 3: IP address redirect (if authorized)
	if e.config.CanTestInternal() {
		ipResp, _ := e.sendTest(ctx, target, "http://127.0.0.1/")

		if ipResp != nil && ipResp.StatusCode < 400 {
			validation["ip_redirect_allowed"] = true
		} else {
			validation["ip_redirect_allowed"] = false
		}
	}

	return validation, nil
}

// sendTest helper
func (e *RedirectAnalysisEngine) sendTest(ctx context.Context, target *core.Target, testURL string) (*core.Response, error) {
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
