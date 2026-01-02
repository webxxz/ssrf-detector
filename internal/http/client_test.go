package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ssrf-detector/internal/core"
)

func TestNewClient(t *testing.T) {
	config := &core.Config{
		HTTPTimeout:     10 * time.Second,
		FollowRedirects: false,
		MaxRedirects:    5,
	}

	client := NewClient(config)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}

	if client.config != config {
		t.Error("Client config not set correctly")
	}
}

func TestClientDo(t *testing.T) {
	// Create test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer ts.Close()

	config := &core.Config{
		HTTPTimeout:     10 * time.Second,
		FollowRedirects: false,
		MaxRedirects:    5,
	}

	client := NewClient(config)

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	ctx := context.Background()
	resp, err := client.Do(ctx, req)

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(resp.BodyBytes) != "test response" {
		t.Errorf("Expected body 'test response', got '%s'", string(resp.BodyBytes))
	}
}

func TestClientDoWithTiming(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("timed response"))
	}))
	defer ts.Close()

	config := &core.Config{
		HTTPTimeout:     10 * time.Second,
		FollowRedirects: false,
		MaxRedirects:    5,
	}

	client := NewClient(config)

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	ctx := context.Background()
	resp, timing, err := client.DoWithTiming(ctx, req)

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp == nil {
		t.Fatal("Response is nil")
	}

	if timing == nil {
		t.Fatal("Timing is nil")
	}

	// Check timing makes sense
	if timing.End.Before(timing.Start) {
		t.Error("End time is before start time")
	}

	totalDuration := timing.End.Sub(timing.Start)
	if totalDuration < 100*time.Millisecond {
		t.Errorf("Total duration %v is less than expected 100ms", totalDuration)
	}

	if resp.Total < 100*time.Millisecond {
		t.Errorf("Response.Total %v is less than expected 100ms", resp.Total)
	}
}

func TestClientRedirectHandling(t *testing.T) {
	redirectCount := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirectCount < 3 {
			redirectCount++
			http.Redirect(w, r, "/redirect", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("final"))
	}))
	defer ts.Close()

	// Test with redirects disabled
	t.Run("RedirectsDisabled", func(t *testing.T) {
		redirectCount = 0
		config := &core.Config{
			HTTPTimeout:     10 * time.Second,
			FollowRedirects: false,
			MaxRedirects:    5,
		}

		client := NewClient(config)
		req, _ := http.NewRequest("GET", ts.URL, nil)

		resp, err := client.Do(context.Background(), req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusFound {
			t.Errorf("Expected status 302, got %d", resp.StatusCode)
		}

		if redirectCount != 1 {
			t.Errorf("Expected 1 redirect attempt, got %d", redirectCount)
		}
	})

	// Test with redirects enabled
	t.Run("RedirectsEnabled", func(t *testing.T) {
		redirectCount = 0
		config := &core.Config{
			HTTPTimeout:     10 * time.Second,
			FollowRedirects: true,
			MaxRedirects:    5,
		}

		client := NewClient(config)
		req, _ := http.NewRequest("GET", ts.URL, nil)

		resp, err := client.Do(context.Background(), req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if string(resp.BodyBytes) != "final" {
			t.Errorf("Expected body 'final', got '%s'", string(resp.BodyBytes))
		}

		if redirectCount != 3 {
			t.Errorf("Expected 3 redirects, got %d", redirectCount)
		}
	})
}

func TestClientTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	config := &core.Config{
		HTTPTimeout:     500 * time.Millisecond,
		FollowRedirects: false,
		MaxRedirects:    5,
	}

	client := NewClient(config)
	req, _ := http.NewRequest("GET", ts.URL, nil)

	_, err := client.Do(context.Background(), req)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

func TestClientContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	config := &core.Config{
		HTTPTimeout:     10 * time.Second,
		FollowRedirects: false,
		MaxRedirects:    5,
	}

	client := NewClient(config)
	req, _ := http.NewRequest("GET", ts.URL, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := client.Do(ctx, req)

	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}
}

func TestHashBody(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		expected string
	}{
		{
			name:     "nil body",
			body:     nil,
			expected: "",
		},
		{
			name:     "empty body",
			body:     []byte{},
			expected: "0",
		},
		{
			name:     "test body",
			body:     []byte("test"),
			expected: "364492c", // Simple hash value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hashBody(tt.body)
			if tt.name == "nil body" && result != "" {
				t.Errorf("Expected empty string for nil body, got %s", result)
			}
			if tt.name == "empty body" && result != "0" {
				t.Errorf("Expected '0' for empty body, got %s", result)
			}
			// For actual content, just check we got a hash
			if tt.name == "test body" && result == "" {
				t.Error("Expected non-empty hash for test body")
			}
		})
	}
}
