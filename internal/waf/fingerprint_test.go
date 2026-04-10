package waf

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestFingerprintWAFCloudflare(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Cf-Ray": []string{"abc"}}}
	if got := FingerprintWAF(resp); got != WAFCloudflare {
		t.Fatalf("expected cloudflare, got %s", got)
	}
}

func TestFingerprintWAFModSecurity(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Server": []string{"Apache"}},
		Body:       io.NopCloser(strings.NewReader("blocked by ModSecurity policy")),
	}
	if got := FingerprintWAF(resp); got != WAFModSecurity {
		t.Fatalf("expected modsecurity, got %s", got)
	}
}
