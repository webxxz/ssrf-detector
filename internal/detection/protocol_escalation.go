package detection

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// ProtocolEscalationEngine tests non-HTTP protocol support
type ProtocolEscalationEngine struct {
	config     *core.Config
	httpClient core.HTTPClient
	oobManager core.OOBManager
}

func NewProtocolEscalationEngine(config *core.Config, httpClient core.HTTPClient, oobManager core.OOBManager) *ProtocolEscalationEngine {
	return &ProtocolEscalationEngine{
		config:     config,
		httpClient: httpClient,
		oobManager: oobManager,
	}
}

func (e *ProtocolEscalationEngine) Name() core.DetectionPhase {
	return core.PhaseProtocolEscalation
}

func (e *ProtocolEscalationEngine) RequiredAuthLevel() core.AuthorizationLevel {
	return core.AuthLevelFull // Protocol escalation requires higher authorization
}

func (e *ProtocolEscalationEngine) DependsOn() []core.DetectionPhase {
	return []core.DetectionPhase{core.PhaseEncodingBoundary}
}

func (e *ProtocolEscalationEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
	startTime := time.Now()
	result := &core.PhaseResult{
		Phase:    e.Name(),
		Success:  false,
		Evidence: make([]core.Evidence, 0),
		Metadata: make(map[string]interface{}),
	}

	// Check authorization
	if !e.config.CanEscalateProtocol() {
		if e.config.Verbose {
			fmt.Printf("[SKIP] Protocol escalation requires AuthLevelFull\n")
		}
		result.Success = true // Not a failure, just skipped
		result.NextPhase = core.PhaseInternalAccess
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Step 1: Safe protocol support detection (error-based)
	protocols, err := e.detectProtocolSupport(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Protocol detection failed: %v\n", err)
		}
	} else {
		result.Metadata["supported_protocols"] = protocols
	}

	// Step 2: Scheme validation testing
	schemeValidation, err := e.testSchemeValidation(ctx, target, state)
	if err != nil {
		if e.config.Verbose {
			fmt.Printf("[WARN] Scheme validation test failed: %v\n", err)
		}
	} else {
		result.Metadata["scheme_validation"] = schemeValidation
	}

	result.Success = true
	result.NextPhase = core.PhaseInternalAccess
	result.Duration = time.Since(startTime)

	return result, nil
}

// detectProtocolSupport tests protocol support via error messages
func (e *ProtocolEscalationEngine) detectProtocolSupport(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]string, error) {
	protocols := make(map[string]string)

	// Test invalid protocol (baseline)
	invalidResp, _ := e.sendTest(ctx, target, "invalid-protocol://test")
	if invalidResp != nil && invalidResp.BodyBytes != nil {
		invalidError := string(invalidResp.BodyBytes)
		protocols["invalid"] = e.extractErrorPattern(invalidError)
	}

	// Only test file:// if authorization allows and with safe path
	if e.config.CanEscalateProtocol() {
		fileResp, _ := e.sendTest(ctx, target, "file:///dev/null")
		if fileResp != nil && fileResp.BodyBytes != nil {
			fileError := string(fileResp.BodyBytes)
			errorPattern := e.extractErrorPattern(fileError)

			if errorPattern != "" && errorPattern != protocols["invalid"] {
				protocols["file"] = errorPattern

				// If file:// has different error, it was recognized/attempted
				if !contains(errorPattern, "Invalid") && !contains(errorPattern, "not supported") {
					// May be supported - create evidence
					evidence := &ProtocolEscalationEvidence{
						Protocol:     "file",
						ErrorPattern: errorPattern,
						Supported:    !contains(errorPattern, "not supported"),
						timestamp:    time.Now(),
					}
					protocols["file_evidence"] = errorPattern
				}
			}
		}
	}

	return protocols, nil
}

// testSchemeValidation tests scheme whitelist/blacklist
func (e *ProtocolEscalationEngine) testSchemeValidation(ctx context.Context, target *core.Target, state *core.ScanState) (map[string]interface{}, error) {
	validation := make(map[string]interface{})

	// Test http (baseline, should be allowed)
	id1, _ := e.oobManager.GenerateIdentifier(target, "scheme-http")
	httpURL, _ := e.oobManager.BuildURL(id1, "/scheme-test")

	resp1, _ := e.sendTest(ctx, target, httpURL)
	callback1, _ := e.oobManager.CheckCallback(id1)

	validation["http_allowed"] = (callback1 != nil)

	// Test https
	id2, _ := e.oobManager.GenerateIdentifier(target, "scheme-https")
	httpsURL := "https://" + id2 + "." + e.config.OOBDomain + "/scheme-test"

	resp2, _ := e.sendTest(ctx, target, httpsURL)
	callback2, _ := e.oobManager.CheckCallback(id2)

	validation["https_allowed"] = (callback2 != nil)

	// Test ftp (safe, just checking rejection)
	ftpResp, _ := e.sendTest(ctx, target, "ftp://test.example.com/")

	if ftpResp != nil {
		validation["ftp_response_code"] = ftpResp.StatusCode
		if ftpResp.BodyBytes != nil {
			ftpError := string(ftpResp.BodyBytes)
			if contains(ftpError, "not supported") || contains(ftpError, "invalid protocol") {
				validation["ftp_blocked"] = true
			}
		}
	}

	return validation, nil
}

// extractErrorPattern extracts error message pattern
func (e *ProtocolEscalationEngine) extractErrorPattern(body string) string {
	patterns := []string{
		"Invalid URL scheme",
		"Protocol not supported",
		"Unsupported protocol",
		"Invalid protocol",
		"Scheme not allowed",
	}

	for _, pattern := range patterns {
		if contains(body, pattern) {
			return pattern
		}
	}

	return ""
}

// sendTest helper
func (e *ProtocolEscalationEngine) sendTest(ctx context.Context, target *core.Target, testURL string) (*core.Response, error) {
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

// ProtocolEscalationEvidence represents protocol support evidence
type ProtocolEscalationEvidence struct {
	Protocol     string
	ErrorPattern string
	Supported    bool
	timestamp    time.Time
}

func (e *ProtocolEscalationEvidence) Type() core.EvidenceType {
	return core.EvidenceProtocolEscalation
}

func (e *ProtocolEscalationEvidence) Score() int {
	if e.Supported {
		return 40 // Significant if actually supported
	}
	return 10
}

func (e *ProtocolEscalationEvidence) Description() string {
	return fmt.Sprintf("Protocol %s support detected (error: %s)", e.Protocol, e.ErrorPattern)
}

func (e *ProtocolEscalationEvidence) Data() interface{} {
	return map[string]interface{}{
		"protocol":  e.Protocol,
		"error":     e.ErrorPattern,
		"supported": e.Supported,
	}
}

func (e *ProtocolEscalationEvidence) Timestamp() time.Time {
	return e.timestamp
}

func (e *ProtocolEscalationEvidence) IsDisqualifying() bool {
	return false
}
