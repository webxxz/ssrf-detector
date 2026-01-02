package detection

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// InternalAccessEngine tests for internal network and cloud metadata access
type InternalAccessEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewInternalAccessEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *InternalAccessEngine {
	return &InternalAccessEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *InternalAccessEngine) Name() core.DetectionPhase {
	return core.PhaseInternalAccess
}

func (e *InternalAccessEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelBasic // Requires at least basic authorization
}

func (e *InternalAccessEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{
		core.PhaseFetchAnalysis,
	}
}

func (e *InternalAccessEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Check authorization
	if !e.config.CanTestInternal() {
		if e.config.Verbose {
			fmt.Printf("[SKIP] Internal IP testing requires AuthLevelBasic and scope permission\n")
		}
		result.Success = true
		result.NextPhase = core.PhaseVerification
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Step 1: Localhost reachability test (safe)
	localhostAccess, err := e.testLocalhostReachability(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Localhost test failed: %v\n", err)
		}
	} else {
		result.Metadata["localhost_access"] = localhostAccess

		if localhostAccess {
			evidence := &core.InternalAccessEvidence{
				InternalIP:   "127.0.0.1",
				ErrorMessage: "Connection attempted",
				//Timestamp:    time.Now(), // Fixed: Timestamp instead of timestamp
			}
			result.Evidence = append(result.Evidence, evidence)
		}
	}

	// Step 2: Cloud metadata detection (if authorized)
	if e.config.CanTestCloudMetadata() {
		cloudAccess, err := e.testCloudMetadataAccess(ctx, target, state)
		if err != nil {
			if e.config.Verbose {
				fmt.Printf("[WARN] Cloud metadata test failed: %v\n", err)
			}
		} else {
			result.Metadata["cloud_metadata"] = cloudAccess

			if cloudAccess["accessible"].(bool) {
				evidence := &core.CloudMetadataEvidence{
					Provider:      cloudAccess["provider"].(string),
					Endpoint:      cloudAccess["endpoint"].(string),
					DataRetrieved: cloudAccess["data"].(string),
					//Timestamp:     time.Now(), // Fixed: Timestamp instead of timestamp
				}
				result.Evidence = append(result.Evidence, evidence)
			}
		}
	}

	// Step 3: RFC1918 timing inference (safe, no actual access)
	if e.config.MaxInternalTests > 0 {
		rfc1918Timing, err := e.inferRFC1918Access(ctx, target, state)
		if err != nil {
			if e.config.Verbose {
				fmt.Printf("[WARN] RFC1918 timing inference failed: %v\n", err)
			}
		} else {
			result.Metadata["rfc1918_inference"] = rfc1918Timing
		}
	}

	result.Success = true
	result.NextPhase = core.PhaseVerification
	result.Duration = time.Since(startTime)

	return result, nil
}

// testLocalhostReachability tests if localhost is reachable
func (e *InternalAccessEngine) testLocalhostReachability(ctx context.Context, target *core.Target, state *core.ScanState) (bool, error) {
	// Test localhost access via timing and error analysis
	// We use timing to infer access without actually fetching data

	resp, timing, _ := e.sendTestWithTiming(ctx, target, "http://127.0.0.1/") // Fixed: ignore err with _

	if timing == nil {
		return false, fmt.Errorf("timing data unavailable")
	}

	responseTime := timing.End.Sub(timing.Start)

	// Analyze response
	if resp != nil {
		// Check error messages
		if resp.BodyBytes != nil {
			body := string(resp.BodyBytes)

			// Connection refused means port reached but nothing listening
			if contains(body, "Connection refused") {
				return true, nil // Localhost reached
			}

			// Connection timeout means localhost filtered
			if contains(body, "timeout") || contains(body, "timed out") {
				// Could be reached but slow
				return true, nil
			}

			// Immediate rejection
			if contains(body, "Invalid") || contains(body, "not allowed") {
				// Check timing - was it instant rejection or after connection?
				if responseTime > 100*time.Millisecond {
					return true, nil // Connection attempted before rejection
				}
				return false, nil // Instant rejection at validation
			}
		}

		// Check status code
		if resp.StatusCode == 200 {
			// Something responded on localhost
			return true, nil
		}
	}

	// Analyze timing
	if state.Baseline != nil {
		// Compare with baseline
		if responseTime < state.Baseline.ResponseTime/2 {
			// Much faster than external - likely local
			return true, nil
		}
	}

	return false, nil
}

// testCloudMetadataAccess tests cloud metadata endpoint access
func (e *InternalAccessEngine) testCloudMetadataAccess(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	result["accessible"] = false

	// Detect cloud provider first (from fingerprinting)
	provider := e.detectCloudProvider(state)
	result["provider"] = provider

	// Test appropriate metadata endpoint
	var endpoint string
	var testPath string

	switch provider {
	case "AWS":
		endpoint = "http://169.254.169.254"
		testPath = "/latest/meta-data/instance-id"
	case "GCP":
		endpoint = "http://metadata.google.internal"
		testPath = "/computeMetadata/v1/instance/id"
	case "Azure":
		endpoint = "http://169.254.169.254"
		testPath = "/metadata/instance?api-version=2021-02-01"
	default:
		// Try AWS by default (most common)
		endpoint = "http://169.254.169.254"
		testPath = "/latest/meta-data/instance-id"
		provider = "AWS"
	}

	result["endpoint"] = endpoint

	// Test metadata access (read-only, safe paths)
	testURL := endpoint + testPath

	resp, timing, _ := e.sendTestWithTiming(ctx, target, testURL) // Fixed: ignore err with _

	if resp != nil && resp.StatusCode == 200 && resp.BodyBytes != nil {
		body := string(resp.BodyBytes)

		// Check if response looks like instance metadata
		if e.isMetadataResponse(body, provider) {
			result["accessible"] = true

			// Extract safe data (instance ID only, not credentials)
			instanceID := e.extractInstanceID(body, provider)
			result["data"] = instanceID

			// Check IMDS version (AWS)
			if provider == "AWS" {
				if resp.StatusCode == 401 || resp.StatusCode == 403 {
					result["imds_version"] = "v2" // Requires token
				} else {
					result["imds_version"] = "v1" // No token required
				}
			}

			return result, nil
		}
	}

	// Check timing even if no response
	if timing != nil && state.Baseline != nil {
		responseTime := timing.End.Sub(timing.Start)

		// Link-local should be very fast
		if responseTime < 50*time.Millisecond {
			result["timing_suggests_local"] = true

			// If fast but no 200, metadata may be restricted
			if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
				result["metadata_restricted"] = true
				result["accessible"] = true // Reachable but protected
			}
		}
	}

	return result, nil
}

// inferRFC1918Access uses timing to infer private IP accessibility
func (e *InternalAccessEngine) inferRFC1918Access(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]interface{}, error) {
	inference := make(map[string]interface{})

	if state.Baseline == nil {
		return inference, fmt.Errorf("baseline required for timing inference")
	}

	// Test a few RFC1918 addresses with timing
	testIPs := []string{
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
	}

	timings := make(map[string]time.Duration)

	for i, ip := range testIPs {
		if i >= e.config.MaxInternalTests {
			break
		}

		testURL := fmt.Sprintf("http://%s/", ip)

		resp, timing, _ := e.sendTestWithTiming(ctx, target, testURL) // Fixed: ignore err with _

		if timing != nil {
			responseTime := timing.End.Sub(timing.Start)
			timings[ip] = responseTime

			// Check if significantly faster than baseline (internal network speed)
			if responseTime < state.Baseline.ResponseTime/3 {
				inference[ip+"_likely_internal"] = true
			}

			// Check error messages
			if resp != nil && resp.BodyBytes != nil {
				body := string(resp.BodyBytes)
				if contains(body, "Connection refused") {
					inference[ip+"_reachable"] = true
				}
			}
		}

		// Rate limiting between tests
		time.Sleep(500 * time.Millisecond)
	}

	inference["timings"] = timings

	return inference, nil
}

// Helper functions

func (e *InternalAccessEngine) detectCloudProvider(state *core.ScanState) string {
	// Detect from client fingerprint or target domain
	if state.ClientFingerprint != nil {
		ua := state.ClientFingerprint.UserAgent

		if contains(ua, "aws") || contains(ua, "amazon") {
			return "AWS"
		}
		if contains(ua, "google") || contains(ua, "gcp") {
			return "GCP"
		}
		if contains(ua, "azure") || contains(ua, "microsoft") {
			return "Azure"
		}
	}

	// Default assumption
	return "AWS" // Most common
}

func (e *InternalAccessEngine) isMetadataResponse(body string, provider string) bool {
	switch provider {
	case "AWS":
		// AWS instance IDs start with "i-"
		if len(body) > 2 && body[0] == 'i' && body[1] == '-' {
			return true
		}
		// AMI IDs start with "ami-"
		if len(body) > 4 && body[:4] == "ami-" {
			return true
		}
	case "GCP":
		// GCP instance IDs are numeric
		if len(body) > 0 && body[0] >= '0' && body[0] <= '9' {
			return true
		}
	case "Azure":
		// Azure returns JSON
		if contains(body, "compute") && contains(body, "vmId") {
			return true
		}
	}

	return false
}

func (e *InternalAccessEngine) extractInstanceID(body string, provider string) string {
	// Extract just the instance ID, nothing sensitive
	switch provider {
	case "AWS":
		// Return first line (instance ID)
		for i, r := range body {
			if r == '\n' {
				return body[:i]
			}
		}
		return body
	case "GCP":
		// Return numeric ID
		return body
	default:
		return "metadata_accessible"
	}
}

func (e *InternalAccessEngine) sendTestWithTiming(ctx context.Context, target *core.Target, testURL string) (*core.Response, *core.RequestTiming, error) {
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
