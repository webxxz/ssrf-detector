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

	waiters map[string][]chan *CallbackEvent
	mu      sync.RWMutex
}

// NewSelfHostedOOBServer creates a lightweight self-hosted OOB callback tracker.
func NewSelfHostedOOBServer(domain string, httpPort, dnsPort int) *OOBServer {
	return &OOBServer{
		Domain:    domain,
		HTTPPort:  httpPort,
		DNSPort:   dnsPort,
		Callbacks: make(map[string]*CallbackEvent),
		waiters:   make(map[string][]chan *CallbackEvent),
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
	waiters := s.waiters[uuid]
	s.Callbacks[uuid] = event
	for _, ch := range waiters {
		select {
		case ch <- event:
		default:
		}
	}
	delete(s.waiters, uuid)
}

// WaitForCallback polls for a callback until timeout.
func (s *OOBServer) WaitForCallback(uuid string, timeout time.Duration) (*CallbackEvent, bool) {
	s.mu.RLock()
	ev, ok := s.Callbacks[uuid]
	s.mu.RUnlock()
	if ok {
		return ev, true
	}

	ch := make(chan *CallbackEvent, 1)
	s.mu.Lock()
	s.waiters[uuid] = append(s.waiters[uuid], ch)
	s.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case event := <-ch:
		return event, true
	case <-timer.C:
		s.mu.Lock()
		waiters := s.waiters[uuid]
		filtered := make([]chan *CallbackEvent, 0, len(waiters))
		for _, waiter := range waiters {
			if waiter != ch {
				filtered = append(filtered, waiter)
			}
		}
		if len(filtered) == 0 {
			delete(s.waiters, uuid)
		} else {
			s.waiters[uuid] = filtered
		}
		s.mu.Unlock()
		return nil, false
	}
}
