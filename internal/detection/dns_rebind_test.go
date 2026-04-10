package detection

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestDetectRebindingWhenResponsesDiffer(t *testing.T) {
	var (
		mu       sync.Mutex
		attempts = map[string]int{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		injected := r.URL.Query().Get("u")
		parsed, err := url.Parse(injected)
		if err != nil {
			http.Error(w, "invalid injected url", http.StatusBadRequest)
			return
		}
		key := parsed.Host

		mu.Lock()
		attempts[key]++
		count := attempts[key]
		mu.Unlock()

		if count == 1 {
			_, _ = w.Write([]byte("external"))
			return
		}
		_, _ = w.Write([]byte("internal"))
	}))
	defer server.Close()

	result := DetectRebinding(server.Client(), server.URL+"?u=%s", "oob.example")
	if result == nil {
		t.Fatal("expected result")
	}
	if !result.Detected {
		t.Fatal("expected detection when responses differ")
	}
	if !strings.Contains(result.FirstResponse, "external") {
		t.Fatal("expected first response marker")
	}
	if !strings.Contains(result.SecondResponse, "internal") {
		t.Fatal("expected second response marker")
	}
	if result.UUID == "" {
		t.Fatal("expected generated uuid")
	}
}

func TestDetectRebindingNotDetectedWhenResponsesMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("same"))
	}))
	defer server.Close()

	result := DetectRebinding(server.Client(), server.URL+"?url={{OOB}}", "oob.example")
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Detected {
		t.Fatal("did not expect detection when responses match")
	}
}

func TestDetectRebindingInputValidation(t *testing.T) {
	if DetectRebinding(nil, "https://example.com", "oob.example").Detected {
		t.Fatal("expected nil client to return non-detected result")
	}
	if DetectRebinding(http.DefaultClient, "", "oob.example").Detected {
		t.Fatal("expected empty target to return non-detected result")
	}
	if DetectRebinding(http.DefaultClient, "https://example.com", "").Detected {
		t.Fatal("expected empty domain to return non-detected result")
	}
}
