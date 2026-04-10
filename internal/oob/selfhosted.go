package oob

import (
	"fmt"
	"sync"
	"time"
)

// CallbackEvent stores observed OOB callback information.
type CallbackEvent struct {
	UUID      string
	Protocol  string
	SourceIP  string
	Path      string
	QueryName string
	Timestamp time.Time
}

// OOBServer provides in-process callback correlation primitives.
type OOBServer struct {
	Domain    string
	HTTPPort  int
	DNSPort   int
	Callbacks map[string]*CallbackEvent

	mu sync.RWMutex
}

// NewSelfHostedOOBServer creates a lightweight self-hosted OOB callback tracker.
func NewSelfHostedOOBServer(domain string, httpPort, dnsPort int) *OOBServer {
	return &OOBServer{
		Domain:    domain,
		HTTPPort:  httpPort,
		DNSPort:   dnsPort,
		Callbacks: make(map[string]*CallbackEvent),
	}
}

// GeneratePayload returns a callback URL for the provided UUID.
func (s *OOBServer) GeneratePayload(uuid string) string {
	return fmt.Sprintf("http://%s.%s/", uuid, s.Domain)
}

// RegisterCallback records an observed callback event.
func (s *OOBServer) RegisterCallback(uuid string, event *CallbackEvent) {
	if event == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Callbacks[uuid] = event
}

// WaitForCallback polls for a callback until timeout.
func (s *OOBServer) WaitForCallback(uuid string, timeout time.Duration) (*CallbackEvent, bool) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		s.mu.RLock()
		ev, ok := s.Callbacks[uuid]
		s.mu.RUnlock()
		if ok {
			return ev, true
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		<-ticker.C
	}
}
