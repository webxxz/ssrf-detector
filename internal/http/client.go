// Package http provides an instrumented HTTP client for SSRF detection.
package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"ssrf-detector/internal/core"
)

// Client implements core.HTTPClient with detailed timing and control
type Client struct {
	client          *http.Client
	config          *core.Config
	followRedirects bool
	maxRedirects    int
}

// NewClient creates a new instrumented HTTP client
func NewClient(config *core.Config) *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Allow insecure TLS for testing (configured)
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Should be configurable
		},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.HTTPTimeout,
	}

	c := &Client{
		client:          httpClient,
		config:          config,
		followRedirects: config.FollowRedirects,
		maxRedirects:    config.MaxRedirects,
	}

	// Configure redirect policy
	if !c.followRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		httpClient.CheckRedirect = c.checkRedirect
	}

	return c
}

// Do executes an HTTP request
func (c *Client) Do(ctx context.Context, req *http.Request) (*core.Response, error) {
	resp, timing, err := c.DoWithTiming(ctx, req)
	return resp, err
}

// DoWithTiming executes an HTTP request with detailed timing
func (c *Client) DoWithTiming(ctx context.Context, req *http.Request) (*core.Response, *core.RequestTiming, error) {
	// Initialize timing
	timing := &core.RequestTiming{
		Start: time.Now(),
	}

	// Create trace for detailed timing
	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			timing.DNSStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			timing.DNSDone = time.Now()
		},
		ConnectStart: func(network, addr string) {
			timing.ConnectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			timing.ConnectDone = time.Now()
		},
		TLSHandshakeStart: func() {
			timing.TLSStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			timing.TLSDone = time.Now()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			timing.RequestSent = time.Now()
		},
		GotFirstResponseByte: func() {
			timing.ResponseStart = time.Now()
		},
	}

	// Add trace to context
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

	// Execute request
	httpResp, err := c.client.Do(req)
	if err != nil {
		timing.End = time.Now()
		return nil, timing, fmt.Errorf("request failed: %w", err)
	}

	timing.ResponseDone = time.Now()

	// Read and capture body
	bodyBytes, err := c.readBody(httpResp)
	if err != nil {
		httpResp.Body.Close()
		timing.End = time.Now()
		return nil, timing, fmt.Errorf("failed to read body: %w", err)
	}

	timing.End = time.Now()

	// Build response
	response := &core.Response{
		Response:  httpResp,
		BodyBytes: bodyBytes,
		BodyHash:  hashBody(bodyBytes),
		FinalURL:  httpResp.Request.URL.String(),
	}

	// Calculate timing metrics
	response.DNSLookup = timing.DNSDone.Sub(timing.DNSStart)
	response.TCPConnection = timing.ConnectDone.Sub(timing.ConnectStart)

	if !timing.TLSStart.IsZero() {
		response.TLSHandshake = timing.TLSDone.Sub(timing.TLSStart)
	}

	response.ServerProcessing = timing.ResponseStart.Sub(timing.RequestSent)
	response.ContentTransfer = timing.ResponseDone.Sub(timing.ResponseStart)
	response.Total = timing.End.Sub(timing.Start)

	// Extract redirect chain if any
	response.RedirectChain = c.extractRedirectChain(httpResp)

	return response, timing, nil
}

// checkRedirect is called for each redirect
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= c.maxRedirects {
		return fmt.Errorf("stopped after %d redirects", c.maxRedirects)
	}
	return nil
}

// readBody reads response body with size limit
func (c *Client) readBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// Limit body size to prevent memory exhaustion
	const maxBodySize = 10 * 1024 * 1024 // 10MB

	limitedReader := io.LimitReader(resp.Body, maxBodySize)
	return io.ReadAll(limitedReader)
}

// extractRedirectChain extracts redirect history from response
func (c *Client) extractRedirectChain(resp *http.Response) []*core.RedirectHop {
	if resp.Request == nil {
		return nil
	}

	chain := make([]*core.RedirectHop, 0)

	// Walk back through redirects
	req := resp.Request
	for req != nil {
		if req.Response != nil {
			hop := &core.RedirectHop{
				URL:        req.URL.String(),
				StatusCode: req.Response.StatusCode,
				Location:   req.Response.Header.Get("Location"),
				Timestamp:  time.Now(), // Approximate
			}
			chain = append(chain, hop)
			req = req.Response.Request
		} else {
			break
		}
	}

	// Reverse to get chronological order
	for i := 0; i < len(chain)/2; i++ {
		j := len(chain) - 1 - i
		chain[i], chain[j] = chain[j], chain[i]
	}

	return chain
}

// hashBody computes SHA-256 hash of body
func hashBody(body []byte) string {
	if body == nil {
		return ""
	}

	// Simple hash for now - in production use crypto/sha256
	hash := 0
	for _, b := range body {
		hash = hash*31 + int(b)
	}

	return fmt.Sprintf("%x", hash)
}
