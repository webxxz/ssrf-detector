package detection

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"ssrf-detector/internal/core"
)

// EncodingBoundaryEngine detects encoding/decoding mismatches
type EncodingBoundaryEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewEncodingBoundaryEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *EncodingBoundaryEngine {
	return &EncodingBoundaryEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *EncodingBoundaryEngine) Name() core.DetectionPhase {
	return core.PhaseEncodingBoundary
}

func (e *EncodingBoundaryEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelNone
}

func (e *EncodingBoundaryEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{core.PhaseParserDifferential}
}

func (e *EncodingBoundaryEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Step 1: Map decode stages
	decodeStages, err := e.mapDecodeStages(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Decode stage mapping failed: %v\n", err)
		}
	} else {
		result.Metadata["decode_stages"] = decodeStages

		if state.ValidatorFingerprint != nil {
			state.ValidatorFingerprint.EncodingHandling.URLDecodeStages = decodeStages
		}
	}

	// Step 2: Test URL encoding depth
	encodingDepth, err := e.testEncodingDepth(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Encoding depth test failed: %v\n", err)
		}
	} else {
		result.Metadata["encoding_depth"] = encodingDepth
	}

	// Step 3: Detect validation boundary timing
	validationStage, err := e.detectValidationStage(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Validation stage detection failed: %v\n", err)
		}
	} else {
		result.Metadata["validation_stage"] = validationStage
	}

	result.Success = true
	result.NextPhase = core.PhaseProtocolEscalation
	result.Duration = time.Since(startTime)

	return result, nil
}

// mapDecodeStages determines how many URL decode passes occur
func (e *EncodingBoundaryEngine) mapDecodeStages(ctx context.Context, target *core.Target, state *core.ScanState) (int, error) {
	// Test with progressively encoded markers

	// Test 1: No encoding (baseline)
	id1, _ := e.oobManager.GenerateIdentifier(target, "enc-0")
	url1, _ := e.oobManager.BuildURL(id1, "/marker-A")

	e.sendTest(ctx, target, url1)
	callback1, _ := e.oobManager.CheckCallback(id1)

	if callback1 == nil {
		return 0, fmt.Errorf("baseline test failed")
	}

	// Baseline: path should be "/marker-A"

	// Test 2: Single encoding (%41 = 'A')
	id2, _ := e.oobManager.GenerateIdentifier(target, "enc-1")
	url2, _ := e.oobManager.BuildURL(id2, "/marker-%41")

	e.sendTest(ctx, target, url2)
	time.Sleep(500 * time.Millisecond)
	callback2, _ := e.oobManager.CheckCallback(id2)

	if callback2 != nil {
		if callback2.Path == "/marker-A" {
			// One decode stage (% decoded to A)

			// Test 3: Double encoding (%2541 = %41)
			id3, _ := e.oobManager.GenerateIdentifier(target, "enc-2")
			url3, _ := e.oobManager.BuildURL(id3, "/marker-%2541")

			e.sendTest(ctx, target, url3)
			time.Sleep(500 * time.Millisecond)
			callback3, _ := e.oobManager.CheckCallback(id3)

			if callback3 != nil {
				if callback3.Path == "/marker-A" {
					// Two decode stages
					return 2, nil
				} else if callback3.Path == "/marker-%41" {
					// Only one decode stage
					return 1, nil
				}
			}

			return 1, nil
		}
	}

	return 0, nil
}

// testEncodingDepth tests double/triple encoding
func (e *EncodingBoundaryEngine) testEncodingDepth(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]interface{}, error) {
	depth := make(map[string]interface{})

	// Generate test marker
	marker := "TEST"

	// Single encode: TEST -> %54%45%53%54 (each char to hex)
	singleEncoded := url.QueryEscape(marker)

	// Double encode
	doubleEncoded := url.QueryEscape(singleEncoded)

	// Test single encoding
	id1, _ := e.oobManager.GenerateIdentifier(target, "depth-1")
	url1 := fmt.Sprintf("http://%s.%s/%s", id1, e.config.OOBDomain, singleEncoded)

	e.sendTest(ctx, target, url1)
	time.Sleep(500 * time.Millisecond)
	callback1, _ := e.oobManager.CheckCallback(id1)

	if callback1 != nil {
		depth["single_encoded_decoded"] = contains(callback1.Path, marker)
	}

	// Test double encoding
	id2, _ := e.oobManager.GenerateIdentifier(target, "depth-2")
	url2 := fmt.Sprintf("http://%s.%s/%s", id2, e.config.OOBDomain, doubleEncoded)

	e.sendTest(ctx, target, url2)
	time.Sleep(500 * time.Millisecond)
	callback2, _ := e.oobManager.CheckCallback(id2)

	if callback2 != nil {
		depth["double_encoded_decoded"] = contains(callback2.Path, marker)
		depth["double_encoded_single_decoded"] = contains(callback2.Path, singleEncoded)
	}

	return depth, nil
}

// detectValidationStage determines where validation occurs relative to decoding
func (e *EncodingBoundaryEngine) detectValidationStage(ctx context.Context, target *core.Target, state *core.ScanState) (string, error) {
	// Test with encoded form of a value that would be blocked if decoded

	// If we had a known blocked pattern (e.g., "127.0.0.1"), we could encode it
	// For safety, we'll test with OOB domain itself

	id1, _ := e.oobManager.GenerateIdentifier(target, "val-stage")
	normalURL, _ := e.oobManager.BuildURL(id1, "/validation-test")

	// Test normal (should work)
	_, _, _ = e.sendTestWithTiming(ctx, target, normalURL)
	callback1, _ := e.oobManager.CheckCallback(id1)

	if callback1 == nil {
		return "unknown", nil
	}

	// Test with URL-encoded version
	id2, _ := e.oobManager.GenerateIdentifier(target, "val-stage-enc")
	encodedURL := url.QueryEscape(normalURL)

	resp2, timing2, _ := e.sendTestWithTiming(ctx, target, encodedURL)
	callback2, _ := e.oobManager.CheckCallback(id2)

	// Analyze results
	if callback2 == nil && resp2 != nil && resp2.StatusCode >= 400 {
		// Encoded version rejected - validator sees encoded form
		if timing2 != nil && timing2.End.Sub(timing2.Start) < 100*time.Millisecond {
			return "before_decode", nil
		}
	}

	if callback2 != nil {
		// Encoded version worked - validation after decode
		return "after_decode", nil
	}

	return "unknown", nil
}

// Helper functions

func (e *EncodingBoundaryEngine) sendTest(ctx context.Context, target *core.Target, testURL string) (*core.Response, error) {
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

func (e *EncodingBoundaryEngine) sendTestWithTiming(ctx context.Context, target *core.Target, testURL string) (*core.Response, *core.RequestTiming, error) {
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
