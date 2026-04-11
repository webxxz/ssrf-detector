package ai

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ScanSession keeps adaptive payload strategy context.
type ScanSession struct {
	SessionID    string
	Target       string
	Attempts     []PayloadAttempt
	Successes    []PayloadAttempt
	Failures     []PayloadAttempt
	WAFResponses []WAFResponse
}

// WAFResponse captures response snippets from blocked requests.
type WAFResponse struct {
	StatusCode  int
	BodySnippet string
}

// PayloadAttempt stores one payload execution outcome.
type PayloadAttempt struct {
	Payload      string
	Strategy     string
	Result       string // blocked | success | timeout | error
	ResponseCode int
	TimingMs     int64
}

// StrategyAdjustment is the next strategy recommendation from AI.
type StrategyAdjustment struct {
	Strategy     string
	PayloadHints []string
	Rationale    string
	UpdatedAt    time.Time
}

// RecordAttempt appends attempt and updates success/failure buckets.
func RecordAttempt(session *ScanSession, attempt PayloadAttempt) {
	if session == nil {
		return
	}
	session.Attempts = append(session.Attempts, attempt)
	switch strings.ToLower(attempt.Result) {
	case "success":
		session.Successes = append(session.Successes, attempt)
	default:
		session.Failures = append(session.Failures, attempt)
	}
}

// AnalyzeSession asks Claude for strategy guidance after each 10 failures.
func AnalyzeSession(session *ScanSession) *StrategyAdjustment {
	if session == nil || len(session.Failures) == 0 || len(session.Failures)%10 != 0 {
		return nil
	}

	start := len(session.Failures) - 10
	if start < 0 {
		start = 0
	}
	recent := session.Failures[start:]

	summary := make([]string, 0, len(recent))
	for _, f := range recent {
		summary = append(summary, fmt.Sprintf("payload=%q strategy=%q result=%s code=%d timing_ms=%d", f.Payload, f.Strategy, f.Result, f.ResponseCode, f.TimingMs))
	}
	wafSummary := make([]string, 0, len(session.WAFResponses))
	for _, wr := range session.WAFResponses {
		wafSummary = append(wafSummary, fmt.Sprintf("status=%d body=%s", wr.StatusCode, wr.BodySnippet))
	}

	system := "You are an SSRF payload strategy optimizer. Return strict JSON only."
	prompt := fmt.Sprintf(`Given these blocked payloads and WAF responses,
what payload strategy should we try next?

Target: %s
Session: %s
Recent failures: %s
WAF responses: %s

Return JSON object with keys:
strategy (string), payload_hints (array of up to 5 strings), rationale (string).`,
		session.Target,
		session.SessionID,
		strings.Join(summary, " || "),
		strings.Join(wafSummary, " || "),
	)

	content, err := callClaude(system, prompt, 600)
	if err != nil {
		return nil
	}

	adj, err := parseStrategyAdjustment(content)
	if err != nil {
		return nil
	}
	adj.UpdatedAt = time.Now()
	return adj
}

func parseStrategyAdjustment(raw string) (*StrategyAdjustment, error) {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)

	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end > start {
		trimmed = trimmed[start : end+1]
	}

	var parsed struct {
		Strategy     string   `json:"strategy"`
		PayloadHints []string `json:"payload_hints"`
		Rationale    string   `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, err
	}
	if strings.TrimSpace(parsed.Strategy) == "" {
		return nil, fmt.Errorf("strategy missing")
	}
	return &StrategyAdjustment{
		Strategy:     parsed.Strategy,
		PayloadHints: parsed.PayloadHints,
		Rationale:    parsed.Rationale,
	}, nil
}
