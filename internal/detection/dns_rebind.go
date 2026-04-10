package detection

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxRebindResponseBodyBytes = 64 * 1024
const rebindResponseFingerprintFormat = "status=%d body=%s"
const rebindProbeURLScheme = "http"

type RebindProbe struct {
	// ExternalIP/InternalIP are metadata placeholders for integrations that drive
	// controlled DNS rebind infrastructure (first resolution vs second resolution).
	ExternalIP string
	InternalIP string
	Domain     string
	UUID       string
}

type RebindResult struct {
	Detected       bool
	FirstResponse  string
	SecondResponse string
	TimingDelta    time.Duration
	UUID           string
}

func DetectRebinding(client *http.Client, targetParam string, oobDomain string) *RebindResult {
	result := &RebindResult{
		UUID: generateRebindUUID(),
	}
	if result.UUID == "" || client == nil || targetParam == "" || oobDomain == "" {
		return result
	}

	probe := RebindProbe{
		Domain: strings.TrimPrefix(fmt.Sprintf("%s.%s", result.UUID, oobDomain), "."),
		UUID:   result.UUID,
	}

	// Intentionally uses HTTP for broad SSRF sink compatibility without requiring
	// wildcard TLS certificates on researcher-controlled callback domains.
	payloadURL := fmt.Sprintf("%s://%s/", rebindProbeURLScheme, probe.Domain)
	targetURL, err := buildRebindTargetURL(targetParam, payloadURL)
	if err != nil {
		return result
	}

	first, firstDuration, err := doRebindAttempt(client, targetURL)
	if err != nil {
		return result
	}
	result.FirstResponse = first

	second, secondDuration, err := doRebindAttempt(client, targetURL)
	if err != nil {
		return result
	}
	result.SecondResponse = second
	result.TimingDelta = durationDelta(firstDuration, secondDuration)
	result.Detected = first != second

	return result
}

func buildRebindTargetURL(targetParam string, payloadURL string) (string, error) {
	if strings.Contains(targetParam, "%s") {
		return fmt.Sprintf(targetParam, url.QueryEscape(payloadURL)), nil
	}
	if strings.Contains(targetParam, "{{OOB}}") {
		return strings.ReplaceAll(targetParam, "{{OOB}}", url.QueryEscape(payloadURL)), nil
	}

	parsed, err := url.Parse(targetParam)
	if err != nil {
		return "", err
	}

	query := parsed.Query()
	for _, key := range []string{"url", "dest", "redirect", "fetch", "image", "path", "target", "uri"} {
		if _, exists := query[key]; exists {
			query.Set(key, payloadURL)
			parsed.RawQuery = query.Encode()
			return parsed.String(), nil
		}
	}

	query.Set("url", payloadURL)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func doRebindAttempt(client *http.Client, targetURL string) (string, time.Duration, error) {
	start := time.Now()
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return "", 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRebindResponseBodyBytes))
	if err != nil {
		return "", 0, err
	}
	duration := time.Since(start)

	return fmt.Sprintf(rebindResponseFingerprintFormat, resp.StatusCode, strings.TrimSpace(string(body))), duration, nil
}

func durationDelta(a, b time.Duration) time.Duration {
	return time.Duration(math.Abs(float64(a - b)))
}

func generateRebindUUID() string {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return ""
	}
	return hex.EncodeToString(randomBytes)
}
