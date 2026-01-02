package core

import (
    "errors"
    "fmt"
    "net/url"
    "time"
)

// DefaultConfig returns a safe default configuration
func DefaultConfig() *Config {
    return &Config{
        AuthLevel:            AuthLevelNone, // Safest default
        Scope:                DefaultScopeConfig(),
        OOBTimeout:           30 * time.Second,
        HTTPTimeout:          10 * time.Second,
        FollowRedirects:      false, // Controlled redirect following
        MaxRedirects:         5,
        UserAgent:            "Mozilla/5.0 (compatible; SSRFDetector/1.0)",
        RateLimit:            10, // 10 req/s
        Concurrency:          5,
        BaselineSamples:      10,
        StatisticalThreshold: 3.0, // 3 sigma
        MaxInternalTests:     10,  // Limit internal IP testing
        DryRun:               false,
        Verbose:              false,
        ReportFormat:         "json",
    }
}

// DefaultScopeConfig returns restrictive scope
func DefaultScopeConfig() ScopeConfig {
    return ScopeConfig{
        InScope:                 []string{},
        OutOfScope:              []string{"*"}, // Deny all by default
        AllowInternalIPs:        false,
        AllowCloudMetadata:      false,
        AllowProtocolEscalation: false,
    }
}

// Validate checks configuration validity
func (c *Config) Validate() error {
    if c.OOBDomain == "" {
        return errors.New("OOB domain must be configured")
    }
    
    // Validate OOB domain is valid
    if _, err := url.Parse("http://" + c.OOBDomain); err != nil {
        return fmt.Errorf("invalid OOB domain: %w", err)
    }
    
    if c.HTTPTimeout <= 0 {
        return errors.New("HTTP timeout must be positive")
    }
    
    if c.OOBTimeout <= 0 {
        return errors.New("OOB timeout must be positive")
    }
    
    if c.RateLimit <= 0 {
        c.RateLimit = 10 // Default
    }
    
    if c.Concurrency <= 0 {
        c.Concurrency = 5 // Default
    }
    
    if c.BaselineSamples < 5 {
        return errors.New("baseline samples must be at least 5")
    }
    
    if c.StatisticalThreshold < 2.0 {
        return errors.New("statistical threshold should be at least 2.0 sigma")
    }
    
    // Safety checks based on authorization level
    if c.AuthLevel == AuthLevelNone {
        if c.Scope.AllowInternalIPs {
            return errors.New("internal IP testing requires at least AuthLevelBasic")
        }
        if c.Scope.AllowProtocolEscalation {
            return errors.New("protocol escalation requires at least AuthLevelFull")
        }
    }
    
    if c.AuthLevel == AuthLevelBasic {
        if c.Scope.AllowProtocolEscalation {
            return errors.New("protocol escalation requires AuthLevelFull")
        }
    }
    
    return nil
}

// String returns human-readable config summary
func (al AuthorizationLevel) String() string {
    switch al {
    case AuthLevelNone:
        return "None (External scanner resources only)"
    case AuthLevelBasic:
        return "Basic (Bug bounty / External assessment)"
    case AuthLevelFull:
        return "Full (Red team / Internal assessment)"
    case AuthLevelExploit:
        return "Exploit (Controlled environment)"
    default:
        return "Unknown"
    }
}

// CanTestInternal returns true if internal IP testing is allowed
func (c *Config) CanTestInternal() bool {
    return c.AuthLevel >= AuthLevelBasic && c.Scope.AllowInternalIPs
}

// CanTestCloudMetadata returns true if cloud metadata testing is allowed
func (c *Config) CanTestCloudMetadata() bool {
    return c.AuthLevel >= AuthLevelBasic && c.Scope.AllowCloudMetadata
}

// CanEscalateProtocol returns true if protocol escalation testing is allowed
func (c *Config) CanEscalateProtocol() bool {
    return c.AuthLevel >= AuthLevelFull && c.Scope.AllowProtocolEscalation
}