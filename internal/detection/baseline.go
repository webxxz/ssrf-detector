package detection

import (
	"context"
	"fmt"
	"time"

	"ssrf-detector/internal/core"
)

// BaselineProfile captures behavioral baseline characteristics for delta comparison.
type BaselineProfile struct {
	StatusCode    int
	ResponseSize  int
	ResponseTime  time.Duration
	ErrorPattern  string
	RedirectChain []string
}

// ProbeResult captures one probe response in baseline-comparable form.
type ProbeResult struct {
	StatusCode    int
	ResponseSize  int
	ResponseTime  time.Duration
	ErrorPattern  string
	RedirectChain []string
}

// CaptureBaselineProfile captures baseline from original/invalid/null probes.
func CaptureBaselineProfile(ctx context.Context, client core.HTTPClient, target *core.Target) (*BaselineProfile, error) {
	if client == nil {
		return nil, fmt.Errorf("http client is nil")
	}
	if target == nil {
		return nil, fmt.Errorf("target is nil")
	}

	probes := make([]*ProbeResult, 0, 3)

	originalProbe, err := executeProbe(ctx, client, cloneTarget(target))
	if err != nil {
		return nil, fmt.Errorf("original baseline probe failed: %w", err)
	}
	probes = append(probes, originalProbe)

	invalidTarget, err := applyInjectionPayload(target, "::INVALID_URL::")
	if err == nil {
		if invalidProbe, probeErr := executeProbe(ctx, client, invalidTarget); probeErr == nil {
			probes = append(probes, invalidProbe)
		}
	}

	nullTarget, err := applyInjectionPayload(target, "")
	if err == nil {
		if nullProbe, probeErr := executeProbe(ctx, client, nullTarget); probeErr == nil {
			probes = append(probes, nullProbe)
		}
	}

	if len(probes) == 0 {
		return nil, fmt.Errorf("no baseline probes captured")
	}

	totalSize := 0
	totalTime := time.Duration(0)
	status := probes[0].StatusCode
	errorPattern := probes[0].ErrorPattern
	redirectChain := probes[0].RedirectChain

	for _, probe := range probes {
		totalSize += probe.ResponseSize
		totalTime += probe.ResponseTime
	}

	return &BaselineProfile{
		StatusCode:    status,
		ResponseSize:  totalSize / len(probes),
		ResponseTime:  totalTime / time.Duration(len(probes)),
		ErrorPattern:  errorPattern,
		RedirectChain: redirectChain,
	}, nil
}

// DiffFromBaseline returns a normalized deviation score in [0,1].
func DiffFromBaseline(baseline *BaselineProfile, result *ProbeResult) float64 {
	if baseline == nil || result == nil {
		return 0
	}

	timingDelta := normalizedDurationDelta(baseline.ResponseTime, result.ResponseTime)
	sizeDelta := normalizedIntDelta(baseline.ResponseSize, result.ResponseSize)

	statusDelta := 0.0
	if baseline.StatusCode != result.StatusCode {
		statusDelta = 1.0
	}

	errorDelta := 0.0
	if baseline.ErrorPattern != result.ErrorPattern {
		if baseline.ErrorPattern == "" || result.ErrorPattern == "" {
			errorDelta = 0.5
		} else {
			errorDelta = 1.0
		}
	}

	score := timingDelta*0.30 + sizeDelta*0.30 + statusDelta*0.20 + errorDelta*0.20
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func executeProbe(ctx context.Context, client core.HTTPClient, target *core.Target) (*ProbeResult, error) {
	req, err := buildRequestFromTarget(target)
	if err != nil {
		return nil, err
	}

	resp, timing, err := client.DoWithTiming(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response")
	}

	result := &ProbeResult{
		StatusCode:    resp.StatusCode,
		ResponseSize:  len(resp.BodyBytes),
		ErrorPattern:  extractErrorPattern(resp),
		RedirectChain: extractRedirectChain(resp),
	}
	if timing != nil {
		result.ResponseTime = timing.End.Sub(timing.Start)
	}
	return result, nil
}

func extractErrorPattern(resp *core.Response) string {
	if resp == nil || resp.BodyBytes == nil {
		return ""
	}

	body := string(resp.BodyBytes)
	patterns := []string{
		"Invalid URL",
		"Malformed URL",
		"DNS resolution failed",
		"Connection refused",
		"Connection timeout",
		"Invalid hostname",
		"Protocol not supported",
		"not allowed",
		"denied",
	}

	for _, pattern := range patterns {
		if contains(body, pattern) {
			return pattern
		}
	}
	return ""
}

func extractRedirectChain(resp *core.Response) []string {
	if resp == nil || len(resp.RedirectChain) == 0 {
		return nil
	}
	chain := make([]string, 0, len(resp.RedirectChain))
	for _, hop := range resp.RedirectChain {
		if hop == nil {
			continue
		}
		chain = append(chain, hop.URL)
	}
	return chain
}

func normalizedDurationDelta(base, probe time.Duration) float64 {
	if base <= 0 {
		return 0
	}
	diff := base - probe
	if diff < 0 {
		diff = -diff
	}
	ratio := float64(diff) / float64(base)
	if ratio > 1 {
		return 1
	}
	return ratio
}

func normalizedIntDelta(base, probe int) float64 {
	if base <= 0 {
		if probe == 0 {
			return 0
		}
		return 1
	}
	diff := base - probe
	if diff < 0 {
		diff = -diff
	}
	ratio := float64(diff) / float64(base)
	if ratio > 1 {
		return 1
	}
	return ratio
}
