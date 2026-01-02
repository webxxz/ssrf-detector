package oob

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"ssrf-detector/internal/core"
)

// Server manages OOB callback servers
type Server struct {
	manager *Manager
	config  *core.Config

	httpServer *http.Server
	dnsServer  *DNSServer
}

// NewServer creates a new OOB server
func NewServer(manager *Manager, config *core.Config) *Server {
	return &Server{
		manager: manager,
		config:  config,
	}
}

// Start starts the OOB servers
func (s *Server) Start(ctx context.Context) error {
	// Start HTTP server
	if err := s.startHTTP(ctx); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	// Start DNS server (optional, based on config)
	if s.config.OOBServerURL != "" {
		if err := s.startDNS(ctx); err != nil {
			return fmt.Errorf("failed to start DNS server: %w", err)
		}
	}

	return nil
}

// startHTTP starts the HTTP callback server
func (s *Server) startHTTP(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.manager.HTTPHandler())

	s.httpServer = &http.Server{
		Addr:         ":8080", // TODO: Make configurable
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if s.config.Verbose {
				fmt.Printf("[ERROR] HTTP server error: %v\n", err)
			}
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return nil
}

// startDNS starts the DNS callback server
func (s *Server) startDNS(ctx context.Context) error {
	s.dnsServer = NewDNSServer(s.manager)

	go func() {
		if err := s.dnsServer.ListenAndServe(":53"); err != nil {
			if s.config.Verbose {
				fmt.Printf("[ERROR] DNS server error: %v\n", err)
			}
		}
	}()

	return nil
}

// Stop stops the OOB servers
func (s *Server) Stop(ctx context.Context) error {
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown HTTP server: %w", err)
		}
	}

	if s.dnsServer != nil {
		if err := s.dnsServer.Stop(); err != nil {
			return fmt.Errorf("failed to stop DNS server: %w", err)
		}
	}

	return nil
}

// DNSServer is a simple DNS server for OOB callbacks
type DNSServer struct {
	manager  *Manager
	listener net.PacketConn
}

// NewDNSServer creates a new DNS server
func NewDNSServer(manager *Manager) *DNSServer {
	return &DNSServer{
		manager: manager,
	}
}

// ListenAndServe starts the DNS server
func (ds *DNSServer) ListenAndServe(addr string) error {
	var err error
	ds.listener, err = net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	defer ds.listener.Close()

	buf := make([]byte, 512) // DNS messages are limited to 512 bytes over UDP

	for {
		n, addr, err := ds.listener.ReadFrom(buf)
		if err != nil {
			return err
		}

		go ds.handleDNSQuery(buf[:n], addr)
	}
}

// Stop stops the DNS server
func (ds *DNSServer) Stop() error {
	if ds.listener != nil {
		return ds.listener.Close()
	}
	return nil
}

// handleDNSQuery processes a DNS query
func (ds *DNSServer) handleDNSQuery(data []byte, addr net.Addr) {
	// Parse DNS query (simplified - in production use a DNS library)
	queryName, queryType := ds.parseDNSQuery(data)

	if queryName == "" {
		return
	}

	// Extract source IP
	sourceIP := ""
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		sourceIP = udpAddr.IP.String()
	}

	// Register DNS callback
	ds.manager.DNSHandler(queryName, queryType, sourceIP)

	// Send DNS response (simplified)
	response := ds.buildDNSResponse(data, queryName)
	ds.listener.WriteTo(response, addr)
}

// parseDNSQuery extracts query name and type (simplified)
func (ds *DNSServer) parseDNSQuery(data []byte) (string, string) {
	// This is a simplified parser
	// In production, use a proper DNS library like github.com/miekg/dns

	if len(data) < 12 {
		return "", ""
	}

	// Skip header (12 bytes) and parse question section
	// Format: length-label-length-label-...-0-type-class

	offset := 12
	var labels []string

	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			break
		}

		offset++
		if offset+length > len(data) {
			return "", ""
		}

		label := string(data[offset : offset+length])
		labels = append(labels, label)
		offset += length
	}

	queryName := ""
	if len(labels) > 0 {
		queryName = fmt.Sprintf("%s", labels[0]) // Just use first label as identifier
	}

	return queryName, "A" // Simplified, always return A record
}

// buildDNSResponse creates a DNS response (simplified)
func (ds *DNSServer) buildDNSResponse(query []byte, queryName string) []byte {
	// This is a simplified response builder
	// In production, use a proper DNS library

	// Copy query and set response flag
	response := make([]byte, len(query)+16) // Add space for answer
	copy(response, query)

	// Set QR flag (response)
	response[2] |= 0x80

	// For now, just return the query with response flag set
	// A proper implementation would include an answer section

	return response[:len(query)]
}
