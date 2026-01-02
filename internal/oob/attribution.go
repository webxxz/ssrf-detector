package oob

import (
    "fmt"
    "net"
    "strings"
    "sync"
    "time"

    "ssrf-detector/internal/core"
)

// SourceAttributor performs source IP attribution
type SourceAttributor struct {
    config        *core.Config
    
    // Target infrastructure IPs (learned or configured)
    targetIPs     map[string]bool
    targetIPsMux  sync.RWMutex
    
    // Known CDN ranges
    cdnRanges     []*net.IPNet
    
    // Known researcher IPs
    researcherIPs map[string]bool
}

// NewSourceAttributor creates a new source attributor
func NewSourceAttributor(config *core.Config) (*SourceAttributor, error) {
    sa := &SourceAttributor{
        config:        config,
        targetIPs:     make(map[string]bool),
        researcherIPs: make(map[string]bool),
    }
    
    // Initialize known CDN ranges
    if err := sa.initCDNRanges(); err != nil {
        return nil, fmt.Errorf("failed to initialize CDN ranges: %w", err)
    }
    
    return sa, nil
}

// Attribute performs source attribution on a callback
func (sa *SourceAttributor) Attribute(callback *core.OOBCallback) error {
    ip := net.ParseIP(callback.SourceIP)
    if ip == nil {
        return fmt.Errorf("invalid IP address: %s", callback.SourceIP)
    }
    
    // Check if from researcher
    callback.IsResearcher = sa.isResearcherIP(callback.SourceIP)
    if callback.IsResearcher {
        return nil // Already determined
    }
    
    // Check if from CDN
    callback.IsCDN = sa.isCDNIP(ip)
    if callback.IsCDN {
        return nil
    }
    
    // Check if from target infrastructure
    callback.IsTargetInfrastructure = sa.isTargetIP(callback.SourceIP)
    
    // Perform PTR lookup for additional context
    if ptr, err := sa.reverseLookup(callback.SourceIP); err == nil {
        callback.PTRRecord = ptr
        
        // Update attribution based on PTR
        if !callback.IsTargetInfrastructure {
            callback.IsTargetInfrastructure = sa.isTargetPTR(ptr)
        }
        
        if !callback.IsCDN {
            callback.IsCDN = sa.isCDNPTR(ptr)
        }
    }
    
    return nil
}

// AddTargetIP adds a known target infrastructure IP
func (sa *SourceAttributor) AddTargetIP(ip string) {
    sa.targetIPsMux.Lock()
    defer sa.targetIPsMux.Unlock()
    sa.targetIPs[ip] = true
}

// AddResearcherIP adds the researcher's IP
func (sa *SourceAttributor) AddResearcherIP(ip string) {
    sa.researcherIPs[ip] = true
}

// isTargetIP checks if IP belongs to target infrastructure
func (sa *SourceAttributor) isTargetIP(ip string) bool {
    sa.targetIPsMux.RLock()
    defer sa.targetIPsMux.RUnlock()
    return sa.targetIPs[ip]
}

// isResearcherIP checks if IP belongs to researcher
func (sa *SourceAttributor) isResearcherIP(ip string) bool {
    return sa.researcherIPs[ip]
}

// isCDNIP checks if IP is in known CDN ranges
func (sa *SourceAttributor) isCDNIP(ip net.IP) bool {
    for _, cidr := range sa.cdnRanges {
        if cidr.Contains(ip) {
            return true
        }
    }
    return false
}

// isTargetPTR checks if PTR record suggests target infrastructure
func (sa *SourceAttributor) isTargetPTR(ptr string) bool {
    // Extract domain from PTR
    // TODO: Implement based on known target domains
    // For now, return false
    return false
}

// isCDNPTR checks if PTR record suggests CDN
func (sa *SourceAttributor) isCDNPTR(ptr string) bool {
    cdnKeywords := []string{
        "cloudflare",
        "akamai",
        "fastly",
        "cloudfront",
        "azure",
        "amazonaws",
        "googleusercontent",
    }
    
    lowerPTR := strings.ToLower(ptr)
    for _, keyword := range cdnKeywords {
        if strings.Contains(lowerPTR, keyword) {
            return true
        }
    }
    
    return false
}

// reverseLookup performs PTR lookup
func (sa *SourceAttributor) reverseLookup(ip string) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    
    names, err := net.DefaultResolver.LookupAddr(ctx, ip)
    if err != nil {
        return "", err
    }
    
    if len(names) == 0 {
        return "", fmt.Errorf("no PTR record found")
    }
    
    return names[0], nil
}

// initCDNRanges initializes known CDN IP ranges
func (sa *SourceAttributor) initCDNRanges() error {
    // Common CDN ranges (subset - in production, use full lists)
    cdnRanges := []string{
        // Cloudflare
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        
        // Akamai (subset)
        "23.0.0.0/12",
        "104.64.0.0/10",
        
        // Fastly (subset)
        "151.101.0.0/16",
        "199.27.72.0/21",
    }
    
    for _, cidr := range cdnRanges {
        _, ipNet, err := net.ParseCIDR(cidr)
        if err != nil {
            return fmt.Errorf("failed to parse CIDR %s: %w", cidr, err)
        }
        sa.cdnRanges = append(sa.cdnRanges, ipNet)
    }
    
    return nil
}