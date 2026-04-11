package payloads

import "testing"

func TestGeneratePayloadsAIMutationFallbackWithoutAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")

	out := GeneratePayloads(&EnvironmentContext{
		CloudProvider:         "aws",
		WAFDetected:           true,
		WAFVendor:             "cloudflare",
		InitialPayloadsFailed: true,
		LastBlockedPayload:    "http://169.254.169.254/latest/meta-data/",
		LastWAFResponse:       "status=403 body=blocked",
		ProxyDetected:         true,
		BackendLang:           "java",
		InternalRange:         []string{"10.0.0.1"},
	})

	if len(out) == 0 {
		t.Fatal("expected payloads")
	}

	for _, p := range out {
		if p.Category == "ai_mutation" {
			t.Fatalf("did not expect ai_mutation payload when API key is unavailable: %+v", p)
		}
	}
}
