//go:build integration
// +build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"ssrf-detector/internal/core"
	"ssrf-detector/internal/detection"
	httpClient "ssrf-detector/internal/http"
	"ssrf-detector/internal/oob"
	"ssrf-detector/internal/scoring"
)

// TestFullScanWorkflow tests the complete detection workflow
func TestFullScanWorkflow(t *testing.T) {
	// Setup mock vulnerable server
	vulnerableServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if url != "" {
			// Simulate server-side fetch
			resp, err := http.Get(url)
			if err == nil {
				defer resp.Body.Close()
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Fetched successfully"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("No URL provided"))
	}))
	defer vulnerableServer.Close()

	// Setup config
	config := core.DefaultConfig()
	config.OOBDomain = "oob.test.com"
	config.AuthLevel = core.AuthLevelBasic
	config.Verbose = false

	// Setup OOB manager
	oobManager, err := oob.NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create OOB manager: %v", err)
	}

	// Setup HTTP client
	client := httpClient.NewClient(config)

	// Setup detection pipeline
	pipeline, err := detection.NewPipeline(config, oobManager, client)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}

	// Create target
	target := &core.Target{
		URL:    mustParseURL(t, vulnerableServer.URL+"?url=test"),
		Method: "GET",
		InjectionPoint: core.InjectionPoint{
			Type: core.InjectionQuery,
			Name: "url",
		},
	}

	// Execute scan
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	state, err := pipeline.Execute(ctx, target)
	if err != nil {
		t.Fatalf("Pipeline execution failed: %v", err)
	}

	// Verify state
	if state == nil {
		t.Fatal("State is nil")
	}

	if state.Baseline == nil {
		t.Error("Baseline not established")
	}

	// Verify phases executed
	expectedPhases := []core.DetectionPhase{
		core.PhaseReachability,
		core.PhaseCapability,
	}

	for _, phase := range expectedPhases {
		if _, exists := state.PhaseResults[phase]; !exists {
			t.Errorf("Phase %s not executed", phase)
		}
	}

	// Attempt to build finding
	scorer := scoring.NewScorer(config)
	finding, err := scorer.BuildFinding(state)

	// We don't expect a finding without proper OOB setup
	// But we should not error
	if err != nil && len(state.Evidence) > 0 {
		t.Logf("Could not build finding: %v", err)
	}

	if finding != nil {
		t.Logf("Finding detected: %s (Confidence: %s)", finding.Type, finding.Confidence)
	}
}

// TestFalsePositiveRejection tests that false positives are rejected
func TestFalsePositiveRejection(t *testing.T) {
	// Setup mock server that only reflects input
	reflectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("URL: " + url)) // Just reflect
	}))
	defer reflectionServer.Close()

	config := core.DefaultConfig()
	config.OOBDomain = "oob.test.com"
	config.Verbose = false

	oobManager, _ := oob.NewManager(config)
	client := httpClient.NewClient(config)
	pipeline, _ := detection.NewPipeline(config, oobManager, client)

	target := &core.Target{
		URL:    mustParseURL(t, reflectionServer.URL+"?url=test"),
		Method: "GET",
		InjectionPoint: core.InjectionPoint{
			Type: core.InjectionQuery,
			Name: "url",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	state, err := pipeline.Execute(ctx, target)
	if err != nil {
		t.Fatalf("Pipeline failed: %v", err)
	}

	// Build finding
	scorer := scoring.NewScorer(config)
	fpChecker := scoring.NewFalsePositiveChecker(config)

	finding, err := scorer.BuildFinding(state)
	if err != nil {
		// Expected - no valid finding
		t.Logf("No finding built (expected): %v", err)
		return
	}

	// If finding was built, it should be rejected as false positive
	if finding != nil {
		err := fpChecker.Check(finding, state)
		if err == nil {
			t.Error("False positive was not rejected")
		} else {
			t.Logf("False positive correctly rejected: %v", err)
		}
	}
}

// TestTimingAnalysis tests timing-based detection
func TestTimingAnalysis(t *testing.T) {
	// Setup server with variable response times
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if url == "slow" {
			time.Sleep(500 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	config := core.DefaultConfig()
	config.OOBDomain = "oob.test.com"
	config.BaselineSamples = 5
	config.StatisticalThreshold = 2.0

	oobManager, _ := oob.NewManager(config)
	client := httpClient.NewClient(config)
	pipeline, _ := detection.NewPipeline(config, oobManager, client)

	target := &core.Target{
		URL:    mustParseURL(t, slowServer.URL+"?url=test"),
		Method: "GET",
		InjectionPoint: core.InjectionPoint{
			Type: core.InjectionQuery,
			Name: "url",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	state, err := pipeline.Execute(ctx, target)
	if err != nil {
		t.Fatalf("Pipeline failed: %v", err)
	}

	// Check baseline was established
	if state.Baseline == nil {
		t.Fatal("Baseline not established")
	}

	if state.Baseline.Samples < config.BaselineSamples {
		t.Errorf("Expected %d baseline samples, got %d",
			config.BaselineSamples, state.Baseline.Samples)
	}

	t.Logf("Baseline: %v ± %v",
		state.Baseline.ResponseTime,
		state.Baseline.ResponseTimeStdDev)
}

// Helper function
func mustParseURL(t *testing.T, rawURL string) *url.URL {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Failed to parse URL %s: %v", rawURL, err)
	}
	return parsedURL
}
