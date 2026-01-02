// Package oob implements out-of-band callback management for SSRF detection.
package oob

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "net"
    "net/http"
    "strings"
    "sync"
    "time"

    "ssrf-detector/internal/core"
)

// Manager implements the OOBManager interface
type Manager struct {
    config        *core.Config
    domain        string
    serverURL     string
    
    // Callback storage
    callbacks     map[string][]*core.OOBCallback
    callbacksMux  sync.RWMutex
    
    // Wait channels for blocking waits
    waitChans     map[string][]chan *core.OOBCallback
    waitChansMux  sync.RWMutex
    
    // Attribution service
    attributor    *SourceAttributor
    
    // Metadata
    startTime     time.Time
}

// NewManager creates a new OOB manager
func NewManager(config *core.Config) (*Manager, error) {
    if config.OOBDomain == "" {
        return nil, fmt.Errorf("OOB domain is required")
    }
    
    m := &Manager{
        config:     config,
        domain:     config.OOBDomain,
        serverURL:  config.OOBServerURL,
        callbacks:  make(map[string][]*core.OOBCallback),
        waitChans:  make(map[string][]chan *core.OOBCallback),
        startTime:  time.Now(),
    }
    
    // Initialize source attributor
    var err error
    m.attributor, err = NewSourceAttributor(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create source attributor: %w", err)
    }
    
    return m, nil
}

// GenerateIdentifier creates a unique correlation ID
func (m *Manager) GenerateIdentifier(target *core.Target, testType string) (string, error) {
    // Generate cryptographically random bytes
    randomBytes := make([]byte, 12)
    if _, err := rand.Read(randomBytes); err != nil {
        return "", fmt.Errorf("failed to generate random bytes: %w", err)
    }
    
    randomStr := hex.EncodeToString(randomBytes)
    
    // Format: testtype-randomhex
    // Example: ssrf-baseline-a1b2c3d4e5f6
    identifier := fmt.Sprintf("%s-%s", 
        sanitizeTestType(testType), 
        randomStr,
    )
    
    return identifier, nil
}

// BuildURL constructs an OOB URL with identifier
func (m *Manager) BuildURL(identifier string, path string) (string, error) {
    // Use subdomain-based identification for DNS tracking
    // Format: identifier.domain.com/path
    
    if path == "" {
        path = "/"
    }
    
    if !strings.HasPrefix(path, "/") {
        path = "/" + path
    }
    
    // Construct URL
    url := fmt.Sprintf("http://%s.%s%s", identifier, m.domain, path)
    
    return url, nil
}

// WaitForCallback waits for a callback with the identifier
func (m *Manager) WaitForCallback(ctx context.Context, identifier string, timeout time.Duration) (*core.OOBCallback, error) {
    // Check if callback already exists
    if cb, found := m.CheckCallback(identifier); found {
        return cb, nil
    }
    
    // Create wait channel
    waitChan := make(chan *core.OOBCallback, 1)
    
    // Register wait channel
    m.waitChansMux.Lock()
    m.waitChans[identifier] = append(m.waitChans[identifier], waitChan)
    m.waitChansMux.Unlock()
    
    // Cleanup on exit
    defer func() {
        m.waitChansMux.Lock()
        chans := m.waitChans[identifier]
        for i, ch := range chans {
            if ch == waitChan {
                m.waitChans[identifier] = append(chans[:i], chans[i+1:]...)
                break
            }
        }
        if len(m.waitChans[identifier]) == 0 {
            delete(m.waitChans, identifier)
        }
        m.waitChansMux.Unlock()
        close(waitChan)
    }()
    
    // Wait for callback or timeout
    timeoutTimer := time.NewTimer(timeout)
    defer timeoutTimer.Stop()
    
    select {
    case <-ctx.Done():
        return nil, ctx.Err()
    case <-timeoutTimer.C:
        return nil, fmt.Errorf("timeout waiting for callback after %s", timeout)
    case callback := <-waitChan:
        return callback, nil
    }
}

// CheckCallback checks if callback was received (non-blocking)
func (m *Manager) CheckCallback(identifier string) (*core.OOBCallback, bool) {
    m.callbacksMux.RLock()
    defer m.callbacksMux.RUnlock()
    
    callbacks, exists := m.callbacks[identifier]
    if !exists || len(callbacks) == 0 {
        return nil, false
    }
    
    // Return most recent callback
    return callbacks[len(callbacks)-1], true
}

// GetCallbacks returns all callbacks for an identifier
func (m *Manager) GetCallbacks(identifier string) []*core.OOBCallback {
    m.callbacksMux.RLock()
    defer m.callbacksMux.RUnlock()
    
    callbacks, exists := m.callbacks[identifier]
    if !exists {
        return nil
    }
    
    // Return copy to prevent external modification
    result := make([]*core.OOBCallback, len(callbacks))
    copy(result, callbacks)
    return result
}

// RegisterCallback stores a callback and notifies waiters
func (m *Manager) RegisterCallback(callback *core.OOBCallback) error {
    if callback == nil {
        return fmt.Errorf("callback cannot be nil")
    }
    
    // Perform source attribution
    if err := m.attributor.Attribute(callback); err != nil {
        // Log but don't fail - attribution is best-effort
        if m.config.Verbose {
            fmt.Printf("[WARN] Attribution failed for %s: %v\n", callback.SourceIP, err)
        }
    }
    
    // Store callback
    m.callbacksMux.Lock()
    m.callbacks[callback.Identifier] = append(m.callbacks[callback.Identifier], callback)
    m.callbacksMux.Unlock()
    
    // Notify waiters
    m.waitChansMux.RLock()
    waiters := m.waitChans[callback.Identifier]
    m.waitChansMux.RUnlock()
    
    for _, ch := range waiters {
        select {
        case ch <- callback:
        default:
            // Channel full or closed, skip
        }
    }
    
    return nil
}

// HTTPHandler returns an HTTP handler for OOB callbacks
func (m *Manager) HTTPHandler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Extract identifier from request
        identifier := m.extractIdentifierFromRequest(r)
        
        if identifier == "" {
            // No valid identifier found
            w.WriteHeader(http.StatusOK)
            w.Write([]byte("OK"))
            return
        }
        
        // Capture request details
        callback := &core.OOBCallback{
            Identifier: identifier,
            Protocol:   "HTTP",
            SourceIP:   extractSourceIP(r),
            SourcePort: extractSourcePort(r),
            Timestamp:  time.Now(),
            Method:     r.Method,
            Path:       r.URL.Path,
            Headers:    r.Header.Clone(),
            UserAgent:  r.UserAgent(),
        }
        
        // Capture body (limited size for safety)
        body := make([]byte, 0, 4096)
        if r.Body != nil {
            buf := make([]byte, 4096)
            n, _ := r.Body.Read(buf)
            body = buf[:n]
            r.Body.Close()
        }
        callback.Body = body
        
        // Register callback
        if err := m.RegisterCallback(callback); err != nil {
            if m.config.Verbose {
                fmt.Printf("[ERROR] Failed to register callback: %v\n", err)
            }
        }
        
        // Return success
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    }
}

// DNSHandler handles DNS callbacks
func (m *Manager) DNSHandler(queryName string, queryType string, sourceIP string) {
    // Extract identifier from DNS query
    identifier := m.extractIdentifierFromDNS(queryName)
    
    if identifier == "" {
        return
    }
    
    callback := &core.OOBCallback{
        Identifier: identifier,
        Protocol:   "DNS",
        SourceIP:   sourceIP,
        Timestamp:  time.Now(),
        QueryType:  queryType,
        QueryName:  queryName,
    }
    
    // Register callback
    if err := m.RegisterCallback(callback); err != nil {
        if m.config.Verbose {
            fmt.Printf("[ERROR] Failed to register DNS callback: %v\n", err)
        }
    }
}

// extractIdentifierFromRequest extracts correlation ID from HTTP request
func (m *Manager) extractIdentifierFromRequest(r *http.Request) string {
    // Try subdomain extraction first
    host := r.Host
    if host == "" {
        host = r.Header.Get("Host")
    }
    
    // Format: identifier.domain.com
    parts := strings.Split(host, ".")
    if len(parts) >= 3 {
        // First part should be identifier
        identifier := parts[0]
        
        // Verify it matches expected format
        if m.isValidIdentifier(identifier) {
            return identifier
        }
    }
    
    // Try path extraction as fallback
    // Format: /identifier/...
    pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
    if len(pathParts) > 0 && m.isValidIdentifier(pathParts[0]) {
        return pathParts[0]
    }
    
    return ""
}

// extractIdentifierFromDNS extracts correlation ID from DNS query
func (m *Manager) extractIdentifierFromDNS(queryName string) string {
    // Format: identifier.domain.com
    parts := strings.Split(queryName, ".")
    if len(parts) >= 3 {
        identifier := parts[0]
        if m.isValidIdentifier(identifier) {
            return identifier
        }
    }
    
    return ""
}

// isValidIdentifier checks if string matches identifier format
func (m *Manager) isValidIdentifier(s string) bool {
    // Format: testtype-hexstring
    parts := strings.Split(s, "-")
    if len(parts) < 2 {
        return false
    }
    
    // Last part should be hex (24 chars)
    hexPart := parts[len(parts)-1]
    if len(hexPart) != 24 {
        return false
    }
    
    // Verify hex
    _, err := hex.DecodeString(hexPart)
    return err == nil
}

// Helper functions

func sanitizeTestType(testType string) string {
    // Remove non-alphanumeric characters
    var result strings.Builder
    for _, r := range testType {
        if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
            result.WriteRune(r)
        } else if r >= 'A' && r <= 'Z' {
            result.WriteRune(r + 32) // Convert to lowercase
        }
    }
    return result.String()
}

func extractSourceIP(r *http.Request) string {
    // Try X-Forwarded-For first (if behind proxy)
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        parts := strings.Split(xff, ",")
        return strings.TrimSpace(parts[0])
    }
    
    // Use RemoteAddr
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return r.RemoteAddr
    }
    return host
}

func extractSourcePort(r *http.Request) int {
    _, portStr, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return 0
    }
    
    var port int
    fmt.Sscanf(portStr, "%d", &port)
    return port
}