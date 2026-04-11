package ai

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PayloadMutationRequest describes WAF-aware mutation input.
type PayloadMutationRequest struct {
	WAFVendor      string
	BlockedPayload string
	WAFResponse    string // status + first 500 chars of body
}

// PayloadMutationResponse carries AI-generated payload mutations.
type PayloadMutationResponse struct {
	Mutations []string
	Strategy  string
}

const payloadMutatorSystemPrompt = `You are an SSRF payload mutation engine. Given:
1. A WAF vendor name
2. A blocked payload
3. The WAF's HTTP response (status + body snippet)

Return a JSON array of 5 mutated payload variants that are
likely to bypass this specific WAF. Use techniques:
decimal IP, octal IP, hex IP, IPv6 mapped, URL encoding,
double encoding, null byte injection, path confusion,
protocol switching, case mutation, whitespace injection.

Return ONLY valid JSON. No explanation.`

// MutateWithAI requests mutation candidates from Claude and parses JSON output.
func MutateWithAI(req PayloadMutationRequest) (*PayloadMutationResponse, error) {
	if strings.TrimSpace(req.BlockedPayload) == "" {
		return nil, fmt.Errorf("blocked payload is required")
	}

	vendor := strings.TrimSpace(req.WAFVendor)
	if vendor == "" {
		vendor = "unknown"
	}

	prompt := fmt.Sprintf("WAF Vendor: %s\nBlocked Payload: %s\nWAF Response: %s", vendor, req.BlockedPayload, strings.TrimSpace(req.WAFResponse))
	content, err := callClaude(payloadMutatorSystemPrompt, prompt, 512)
	if err != nil {
		return nil, err
	}

	mutations, err := parseMutationArray(content)
	if err != nil {
		return nil, err
	}

	return &PayloadMutationResponse{
		Mutations: mutations,
		Strategy:  "ai_waf_specific",
	}, nil
}

func parseMutationArray(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)

	start := strings.Index(trimmed, "[")
	end := strings.LastIndex(trimmed, "]")
	if start >= 0 && end > start {
		trimmed = trimmed[start : end+1]
	}

	var parsed []string
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse mutations JSON: %w", err)
	}

	uniq := make([]string, 0, len(parsed))
	seen := map[string]struct{}{}
	for _, m := range parsed {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		uniq = append(uniq, m)
		if len(uniq) == 5 {
			break
		}
	}
	if len(uniq) == 0 {
		return nil, fmt.Errorf("no valid mutations returned")
	}
	return uniq, nil
}
