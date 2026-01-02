package detection

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// ParserDifferentialEngine identifies differences between validator and HTTP client URL parsing
type ParserDifferentialEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewParserDifferentialEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *ParserDifferentialEngine {
	return &ParserDifferentialEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *ParserDifferentialEngine) Name() core.DetectionPhase {
	return core.PhaseParserDifferential
}

func (e *ParserDifferentialEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelNone
}

func (e *ParserDifferentialEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{core.PhaseTrustBoundary}
}

func (e *ParserDifferentialEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	differentials := make(map[string]bool)

	// Step 1: IP representation testing (using scanner IP)
	ipDiff, err := e.testIPRepresentations(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] IP representation test failed: %v\n", err)
		}
	} else {
		differentials["ip_representation"] = ipDiff
		result.Metadata["ip_differential"] = ipDiff
	}

	// Step 2: Authority section parsing
	authDiff, err := e.testAuthoritySectionParsing(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Authority parsing test failed: %v\n", err)
		}
	} else {
		differentials["authority_parsing"] = authDiff
		result.Metadata["authority_differential"] = authDiff
	}

	// Step 3: Scheme parsing
	schemeDiff, err := e.testSchemeParsing(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Scheme parsing test failed: %v\n", err)
		}
	} else {
		differentials["scheme_parsing"] = schemeDiff
		result.Metadata["scheme_differential"] = schemeDiff
	}

	// Step 4: Fragment handling
	fragmentDiff, err := e.testFragmentHandling(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Fragment handling test failed: %v\n", err)
		}
	} else {
		differentials["fragment_handling"] = fragmentDiff
		result.Metadata["fragment_differential"] = fragmentDiff
	}

	// Check if any differential found
	foundDifferential := false
	for _, hasDiff := range differentials {
		if hasDiff {
			foundDifferential = true
			break
		}
	}

	if foundDifferential {
		result.Success = true
		result.NextPhase = core.PhaseEncodingBoundary

		// Create evidence
		evidence := &ParserDifferentialEvidence{
			DifferentialType: "parser_mismatch",
			Details:          differentials,
			timestamp:        time.Now(),
		}
		result.Evidence = append(result.Evidence, evidence)
	} else {
		result.Success = true // Continue even if no differential
		result.NextPhase = core.PhaseEncodingBoundary
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// testIPRepresentations tests various IP address formats with scanner IP
func (e *ParserDifferentialEngine) testIPRepresentations(ctx context.Context, target *core.Target, state *core.ScanState) (bool, error) {
	// We'll use scanner's OOB domain IP for safe testing
	// In production, you'd resolve the OOB domain to get its IP

	// For this example, we'll test with documented representations
	// using the OOB domain itself, not actual IPs (safer)

	identifier, _ := e.oobManager.GenerateIdentifier(target, "ip-repr")
	baseURL, _ := e.oobManager.BuildURL(identifier, "/ip-test")

	// Test 1: Standard form (baseline)
	resp1, _ := e.sendTest(ctx, target, baseURL)
	callback1, _ := e.oobManager.CheckCallback(identifier)

	if callback1 == nil {
		// If baseline doesn't work, can't test differentials
		return false, nil
	}

	// Test 2: Case variation (should work identically)
	identifier2, _ := e.oobManager.GenerateIdentifier(target, "ip-repr-case")
	caseURL := "HTTP://" + identifier2 + "." + e.config.OOBDomain + "/case-test"

	resp2, _ := e.sendTest(ctx, target, caseURL)
	callback2, _ := e.oobManager.CheckCallback(identifier2)

	// If one works and other doesn't, there's a case sensitivity differential
	if (callback1 != nil) != (callback2 != nil) {
		return true, nil // Differential found
	}

	return false, nil
}

// testAuthoritySectionParsing tests @ symbol handling
func (e *ParserDifferentialEngine) testAuthoritySectionParsing(ctx context.Context, target *core.Target, state *core.ScanState) (bool, error) {
	// Test: userinfo@ confusion
	identifier1, _ := e.oobManager.GenerateIdentifier(target, "auth-base")
	baseURL, _ := e.oobManager.BuildURL(identifier1, "/auth-test")

	// Send baseline
	resp1, _ := e.sendTest(ctx, target, baseURL)
	callback1, _ := e.oobManager.CheckCallback(identifier1)

	if callback1 == nil {
		return false, nil
	}

	// Test with @ in userinfo position
	identifier2, _ := e.oobManager.GenerateIdentifier(target, "auth-userinfo")

	// Format: http://fake@identifier.oob.domain/test
	// Some parsers see "identifier.oob.domain" as host
	// Others see "fake@identifier.oob.domain" as host
	userInfoURL := fmt.Sprintf("http://fake@%s.%s/userinfo-test", identifier2, e.config.OOBDomain)

	resp2, _ := e.sendTest(ctx, target, userInfoURL)
	callback2, _ := e.oobManager.CheckCallback(identifier2)

	// Check if callback received (indicates @ parsed correctly by client)
	if callback2 != nil {
		// Check validator behavior from response
		if resp2 != nil && resp2.StatusCode >= 400 {
			// Validator rejected but client would accept
			return true, nil // Differential found
		}
	}

	return false, nil
}

// testSchemeParsing tests URL scheme parsing
func (e *ParserDifferentialEngine) testSchemeParsing(ctx context.Context, target *core.Target, state *core.ScanState) (bool, error) {
	identifier, _ := e.oobManager.GenerateIdentifier(target, "scheme")
	baseURL, _ := e.oobManager.BuildURL(identifier, "/scheme-test")

	// Test 1: Standard lowercase
	resp1, _ := e.sendTest(ctx, target, baseURL)
	callback1, _ := e.oobManager.CheckCallback(identifier)

	if callback1 == nil {
		return false, nil
	}

	// Test 2: Uppercase scheme
	identifier2, _ := e.oobManager.GenerateIdentifier(target, "scheme-upper")
	upperURL := "HTTP://" + identifier2 + "." + e.config.OOBDomain + "/upper"

	resp2, timing2, _ := e.sendTestWithTiming(ctx, target, upperURL)
	callback2, _ := e.oobManager.CheckCallback(identifier2)

	// Check for differential
	if (callback1 != nil) != (callback2 != nil) {
		return true, nil
	}

	// Also check timing - if validator rejects quickly vs processes
	if resp2 != nil && timing2 != nil && state.Baseline != nil {
		respTime := timing2.End.Sub(timing2.Start)
		if respTime < state.Baseline.ResponseTime/2 && resp2.StatusCode >= 400 {
			// Quick rejection suggests validator saw uppercase as invalid
			// But need to check if client would accept
			return true, nil
		}
	}

	return false, nil
}

// testFragmentHandling tests URL fragment parsing
func (e *ParserDifferentialEngine) testFragmentHandling(ctx context.Context, target *core.Target, state *core.ScanState) (bool, error) {
	identifier1, _ := e.oobManager.GenerateIdentifier(target, "frag-base")
	baseURL, _ := e.oobManager.BuildURL(identifier1, "/fragment-test")

	resp1, _ := e.sendTest(ctx, target, baseURL)
	callback1, _ := e.oobManager.CheckCallback(identifier1)

	if callback1 == nil {
		return false, nil
	}

	// Test with fragment
	identifier2, _ := e.oobManager.GenerateIdentifier(target, "frag-test")
	fragmentURL := fmt.Sprintf("http://%s.%s/test#fragment", identifier2, e.config.OOBDomain)

	resp2, _ := e.sendTest(ctx, target, fragmentURL)
	callback2, _ := e.oobManager.CheckCallback(identifier2)

	// Check if fragment was sent to server (non-standard)
	if callback2 != nil {
		if callback2.Path != "" && contains(callback2.Path, "#") {
			// Fragment was sent - parser doesn't strip it
			// This is a differential if validator expects standard behavior
			return true, nil
		}
	}

	return false, nil
}

// Helper functions

func (e *ParserDifferentialEngine) sendTest(ctx context.Context, target *core.Target, testURL string) (*core.Response, error) {
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

func (e *ParserDifferentialEngine) sendTestWithTiming(ctx context.Context, target *core.Target, testURL string) (*core.Response, *core.RequestTiming, error) {
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

// ParserDifferentialEvidence represents parser mismatch evidence
type ParserDifferentialEvidence struct {
	DifferentialType string
	Details          map[string]bool
	timestamp        time.Time
}

func (e *ParserDifferentialEvidence) Type() core.EvidenceType {
	return core.EvidenceParserDifferential
}

func (e *ParserDifferentialEvidence) Score() int {
	return 25
}

func (e *ParserDifferentialEvidence) Description() string {
	return fmt.Sprintf("Parser differential detected: %s", e.DifferentialType)
}

func (e *ParserDifferentialEvidence) Data() interface{} {
	return e.Details
}

func (e *ParserDifferentialEvidence) Timestamp() time.Time {
	return e.timestamp
}

func (e *ParserDifferentialEvidence) IsDisqualifying() bool {
	return false
}
