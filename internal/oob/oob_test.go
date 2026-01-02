package oob

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ssrf-detector/internal/core"
)

func TestManager_GenerateIdentifier(t *testing.T) {
	config := core.DefaultConfig()
	config.OOBDomain = "oob.example.com"

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	target := &core.Target{}
	id, err := manager.GenerateIdentifier(target, "ssrf-baseline")
	if err != nil {
		t.Fatalf("Failed to generate identifier: %v", err)
	}

	if len(id) == 0 {
		t.Error("Generated identifier is empty")
	}

	// Verify format: testtype-hexstring
	if !manager.isValidIdentifier(id) {
		t.Errorf("Generated identifier %s is not valid", id)
	}
}

func TestManager_BuildURL(t *testing.T) {
	config := core.DefaultConfig()
	config.OOBDomain = "oob.example.com"

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	url, err := manager.BuildURL("ssrfbaseline-a1b2c3d4e5f6a1b2c3d4e5f6", "/test")
	if err != nil {
		t.Fatalf("Failed to build URL: %v", err)
	}

	expected := "http://ssrfbaseline-a1b2c3d4e5f6a1b2c3d4e5f6.oob.example.com/test"
	if url != expected {
		t.Errorf("Expected URL %s, got %s", expected, url)
	}
}

func TestManager_WaitForCallback(t *testing.T) {
	config := core.DefaultConfig()
	config.OOBDomain = "oob.example.com"

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	identifier := "test-a1b2c3d4e5f6a1b2c3d4e5f6"

	// Simulate callback in background
	go func() {
		time.Sleep(100 * time.Millisecond)
		callback := &core.OOBCallback{
			Identifier: identifier,
			Protocol:   "HTTP",
			SourceIP:   "203.0.113.50",
			Timestamp:  time.Now(),
		}
		manager.RegisterCallback(callback)
	}()

	// Wait for callback
	ctx := context.Background()
	callback, err := manager.WaitForCallback(ctx, identifier, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to wait for callback: %v", err)
	}

	if callback == nil {
		t.Fatal("Callback is nil")
	}

	if callback.SourceIP != "203.0.113.50" {
		t.Errorf("Expected source IP 203.0.113.50, got %s", callback.SourceIP)
	}
}

func TestManager_HTTPHandler(t *testing.T) {
	config := core.DefaultConfig()
	config.OOBDomain = "oob.example.com"

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	handler := manager.HTTPHandler()

	// Create test request
	req := httptest.NewRequest("GET", "http://test-a1b2c3d4e5f6a1b2c3d4e5f6.oob.example.com/callback", nil)
	req.Header.Set("User-Agent", "Python-urllib/3.9")

	w := httptest.NewRecorder()
	handler(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check callback was registered
	callback, found := manager.CheckCallback("test-a1b2c3d4e5f6a1b2c3d4e5f6")
	if !found {
		t.Fatal("Callback not registered")
	}

	if callback.UserAgent != "Python-urllib/3.9" {
		t.Errorf("Expected User-Agent Python-urllib/3.9, got %s", callback.UserAgent)
	}
}

func TestSourceAttributor_Attribution(t *testing.T) {
	config := core.DefaultConfig()
	config.OOBDomain = "oob.example.com"

	attributor, err := NewSourceAttributor(config)
	if err != nil {
		t.Fatalf("Failed to create attributor: %v", err)
	}

	// Add researcher IP
	attributor.AddResearcherIP("192.0.2.1")

	// Test researcher IP attribution
	callback := &core.OOBCallback{
		SourceIP: "192.0.2.1",
	}

	err = attributor.Attribute(callback)
	if err != nil {
		t.Fatalf("Attribution failed: %v", err)
	}

	if !callback.IsResearcher {
		t.Error("Expected callback to be attributed to researcher")
	}

	// Test CDN IP attribution (Cloudflare)
	callback2 := &core.OOBCallback{
		SourceIP: "104.16.0.1",
	}

	err = attributor.Attribute(callback2)
	if err != nil {
		t.Fatalf("Attribution failed: %v", err)
	}

	if !callback2.IsCDN {
		t.Error("Expected callback to be attributed to CDN")
	}
}
