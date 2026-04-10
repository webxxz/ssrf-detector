package detection

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"ssrf-detector/internal/core"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func TestCloneTargetDeepCopy(t *testing.T) {
	original := &core.Target{
		URL:     mustURL(t, "https://example.com/a?x=1"),
		Method:  "POST",
		Headers: http.Header{"X-Test": []string{"v1"}},
		Body:    []byte(`{"url":"https://a"}`),
	}
	cloned := cloneTarget(original)

	cloned.URL.Path = "/changed"
	cloned.Headers.Set("X-Test", "v2")
	cloned.Body[0] = 'X'

	if original.URL.Path == cloned.URL.Path {
		t.Fatal("expected URL deep copy")
	}
	if original.Headers.Get("X-Test") == cloned.Headers.Get("X-Test") {
		t.Fatal("expected headers deep copy")
	}
	if string(original.Body) == string(cloned.Body) {
		t.Fatal("expected body deep copy")
	}
}

func TestApplyInjectionPayloadByType(t *testing.T) {
	tests := []struct {
		name   string
		target *core.Target
		check  func(*testing.T, *core.Target)
	}{
		{
			name: "query",
			target: &core.Target{
				URL:    mustURL(t, "https://example.com/fetch?url=old"),
				Method: "GET",
				InjectionPoint: core.InjectionPoint{
					Type: core.InjectionQuery, Name: "url",
				},
			},
			check: func(t *testing.T, target *core.Target) {
				if target.URL.Query().Get("url") != "https://new.example" {
					t.Fatal("query param not injected")
				}
			},
		},
		{
			name: "header",
			target: &core.Target{
				URL:     mustURL(t, "https://example.com"),
				Method:  "GET",
				Headers: http.Header{},
				InjectionPoint: core.InjectionPoint{
					Type: core.InjectionHeader, Name: "X-Forwarded-Host",
				},
			},
			check: func(t *testing.T, target *core.Target) {
				if target.Headers.Get("X-Forwarded-Host") != "https://new.example" {
					t.Fatal("header not injected")
				}
			},
		},
		{
			name: "path",
			target: &core.Target{
				URL:    mustURL(t, "https://example.com/a/b"),
				Method: "GET",
				InjectionPoint: core.InjectionPoint{
					Type: core.InjectionPath, Position: 1,
				},
			},
			check: func(t *testing.T, target *core.Target) {
				if !strings.Contains(target.URL.Path, "https:%2F%2Fnew.example") {
					t.Fatal("path segment not injected")
				}
			},
		},
		{
			name: "body",
			target: &core.Target{
				URL:    mustURL(t, "https://example.com"),
				Method: "POST",
				Headers: http.Header{
					"Content-Type": []string{"application/x-www-form-urlencoded"},
				},
				Body: []byte("url=old"),
				InjectionPoint: core.InjectionPoint{
					Type: core.InjectionBody, Name: "url",
				},
			},
			check: func(t *testing.T, target *core.Target) {
				values, err := url.ParseQuery(string(target.Body))
				if err != nil || values.Get("url") != "https://new.example" {
					t.Fatal("body param not injected")
				}
			},
		},
		{
			name: "json",
			target: &core.Target{
				URL:     mustURL(t, "https://example.com"),
				Method:  "POST",
				Headers: http.Header{"Content-Type": []string{"application/json"}},
				Body:    []byte(`{"url":"old"}`),
				InjectionPoint: core.InjectionPoint{
					Type: core.InjectionJSON, Name: "url",
				},
			},
			check: func(t *testing.T, target *core.Target) {
				if !strings.Contains(string(target.Body), "https://new.example") {
					t.Fatal("json field not injected")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			injected, err := applyInjectionPayload(tc.target, "https://new.example")
			if err != nil {
				t.Fatalf("applyInjectionPayload failed: %v", err)
			}
			tc.check(t, injected)
		})
	}
}

func TestApplyInjectionPayloadMalformedJSON(t *testing.T) {
	target := &core.Target{
		URL:    mustURL(t, "https://example.com"),
		Method: "POST",
		Body:   []byte(`{invalid`),
		InjectionPoint: core.InjectionPoint{
			Type: core.InjectionJSON, Name: "url",
		},
	}

	_, err := applyInjectionPayload(target, "https://new.example")
	if err == nil {
		t.Fatal("expected error for malformed json")
	}
}

func TestBuildRequestFromTarget(t *testing.T) {
	target := &core.Target{
		URL:    mustURL(t, "https://example.com"),
		Method: "POST",
		Headers: http.Header{
			"X-Test": []string{"abc"},
		},
		Body: []byte("test-body"),
	}

	req, err := buildRequestFromTarget(target)
	if err != nil {
		t.Fatalf("buildRequestFromTarget failed: %v", err)
	}

	if req.Header.Get("X-Test") != "abc" {
		t.Fatal("expected propagated headers")
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "test-body" {
		t.Fatal("expected propagated body")
	}
}
