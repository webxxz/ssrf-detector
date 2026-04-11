package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultClaudeModel   = "claude-3-5-sonnet-20241022"
	anthropicMessagesURL = "https://api.anthropic.com/v1/messages"
	maxClaudeErrorLength = 500
)

type claudeMessageRequest struct {
	Model       string                 `json:"model"`
	MaxTokens   int                    `json:"max_tokens"`
	Temperature float64                `json:"temperature,omitempty"`
	System      string                 `json:"system,omitempty"`
	Messages    []claudeMessageContent `json:"messages"`
}

type claudeMessageContent struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeMessageResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func callClaude(systemPrompt, userPrompt string, maxTokens int) (string, error) {
	apiKey := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	if apiKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY is not configured")
	}

	model := strings.TrimSpace(os.Getenv("ANTHROPIC_MODEL"))
	if model == "" {
		model = defaultClaudeModel
	}

	if maxTokens <= 0 {
		maxTokens = 1024
	}

	reqBody := claudeMessageRequest{
		Model:       model,
		MaxTokens:   maxTokens,
		Temperature: 0.2,
		System:      systemPrompt,
		Messages: []claudeMessageContent{
			{Role: "user", Content: userPrompt},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal anthropic request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, anthropicMessagesURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("build anthropic request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read anthropic response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		trimmed := string(respBody)
		if len(trimmed) > maxClaudeErrorLength {
			trimmed = trimmed[:maxClaudeErrorLength]
		}
		return "", fmt.Errorf("anthropic api status %d: %s", resp.StatusCode, trimmed)
	}

	var parsed claudeMessageResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("parse anthropic response: %w", err)
	}

	var out strings.Builder
	for _, c := range parsed.Content {
		if c.Type == "text" {
			out.WriteString(c.Text)
		}
	}

	text := strings.TrimSpace(out.String())
	if text == "" {
		return "", fmt.Errorf("anthropic response contained no text")
	}
	return text, nil
}
