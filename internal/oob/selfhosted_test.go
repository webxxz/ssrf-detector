package oob

import (
	"testing"
	"time"
)

func TestOOBServerGeneratePayload(t *testing.T) {
	s := NewSelfHostedOOBServer("oob.example.com", 8080, 53)
	got := s.GeneratePayload("abc123")
	if got != "http://abc123.oob.example.com/" {
		t.Fatalf("unexpected payload: %s", got)
	}
}

func TestOOBServerWaitForCallback(t *testing.T) {
	s := NewSelfHostedOOBServer("oob.example.com", 8080, 53)
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.RegisterCallback("id1", &CallbackEvent{UUID: "id1", Protocol: "HTTP", Timestamp: time.Now()})
	}()
	if _, ok := s.WaitForCallback("id1", 500*time.Millisecond); !ok {
		t.Fatal("expected callback")
	}
}
