# Remaining Documentation Files

## File 3: `docs/USAGE_GUIDE.md`

```markdown
# SSRF Detector - Usage Guide

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Command Line Interface](#command-line-interface)
5. [Authorization Levels](#authorization-levels)
6. [Output Formats](#output-formats)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

## Installation

### From Source

```bash
# Clone repository
git clone https://github.com/yourusername/ssrf-detector.git
cd ssrf-detector

# Run installation script
./scripts/install.sh

# Or manual build
make build

# Verify installation
ssrfdetect --version
```

### Using Docker

```bash
# Pull image
docker pull ssrf-detector:latest

# Or build locally
docker build -t ssrf-detector .

# Run
docker run ssrf-detector --help
```

### Using Go Install

```bash
go install github.com/yourusername/ssrf-detector/cmd/ssrfdetect@latest
```

## Quick Start

### Prerequisites

**1. Setup OOB (Out-of-Band) Domain**

You MUST have a domain for callback detection:

```bash
# Option A: Use interact.sh (easy, free)
OOB_DOMAIN="random-identifier.interact.sh"

# Option B: Setup your own (recommended for production)
./scripts/setup_oob_server.sh
```

**2. Configure DNS**

For your own domain, add these DNS records:
```
A     oob.yourdomain.com    →  YOUR_SERVER_IP
A     *.oob.yourdomain.com  →  YOUR_SERVER_IP
```

### Your First Scan

```bash
# Basic external scan (safest)
ssrfdetect \
    -u "https://example.com/fetch?url=test" \
    -p url \
    --oob-domain your-oob-domain.com \
    -v

# Expected output:
# [+] Starting scan of https://example.com/fetch
# [+] Authorization level: None (External scanner resources only)
# [+] Injection point: url (query_parameter)
# [PHASE] Executing reachability
# [PHASE] Executing capability_discovery
# ...
# [+] Scan completed in 45.2s
# === Scan Summary ===
# Total findings: 1
#   High: 1
```

## Configuration

### Configuration File

Create `~/.config/ssrfdetect/config.yaml`:

```yaml
# OOB Configuration
oob_domain: "oob.yourdomain.com"
oob_timeout: "30s"

# Authorization
auth_level: "none"  # none, basic, full, exploit

# HTTP Settings
http_timeout: "10s"
follow_redirects: false
max_redirects: 5

# Performance
rate_limit: 10
concurrency: 5

# Detection
baseline_samples: 10
statistical_threshold: 3.0

# Scope
scope:
  in_scope:
    - "*.example.com"
  out_of_scope:
    - "*.internal.example.com"
  allow_internal_ips: false
  allow_cloud_metadata: false
```

### Environment Variables

```bash
export SSRF_OOB_DOMAIN="oob.yourdomain.com"
export SSRF_AUTH_LEVEL="basic"
export SSRF_VERBOSE="true"
```

## Command Line Interface

### Basic Syntax

```bash
ssrfdetect [OPTIONS] -u <URL> -p <PARAMETER> --oob-domain <DOMAIN>
```

### Required Arguments

| Flag | Description | Example |
|------|-------------|---------|
| `-u, --url` | Target URL to test | `https://example.com/fetch` |
| `-p, --param` | Parameter name to inject | `url` |
| `--oob-domain` | Out-of-band callback domain | `oob.example.com` |

### Optional Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `--auth-level` | Authorization level (none/basic/full/exploit) | `none` |
| `-o, --output` | Output file path | stdout |
| `-f, --format` | Report format (json/markdown/csv) | `json` |
| `-v, --verbose` | Verbose output | `false` |
| `--allow-internal` | Allow internal IP testing | `false` |
| `--allow-cloud-metadata` | Allow cloud metadata testing | `false` |
| `--allow-protocol-escalation` | Allow protocol escalation | `false` |
| `-h, --help` | Show help | - |
| `--version` | Show version | - |

### Examples

#### Example 1: Basic Bug Bounty Scan

```bash
ssrfdetect \
    -u "https://target.com/api/import?source=" \
    -p source \
    --oob-domain oob.example.com \
    --auth-level basic \
    --allow-cloud-metadata \
    -f markdown \
    -o report.md \
    -v
```

#### Example 2: Red Team Assessment

```bash
ssrfdetect \
    -u "https://internal.corp.com/webhook?callback_url=" \
    -p callback_url \
    --oob-domain callbacks.redteam.local \
    --auth-level full \
    --allow-internal \
    --allow-cloud-metadata \
    --allow-protocol-escalation \
    -f json \
    -o assessment.json \
    -v
```

#### Example 3: Bulk Testing

```bash
# From URL list
while read url; do
    ssrfdetect -u "$url" -p url --oob-domain oob.example.com -f csv >> results.csv
done < urls.txt
```

#### Example 4: Docker Usage

```bash
docker run \
    -v $(pwd)/reports:/app/reports \
    -e OOB_DOMAIN=oob.example.com \
    ssrf-detector \
    -u "https://example.com/fetch" \
    -p url \
    -o /app/reports/scan.json
```

## Authorization Levels

### Level 0: None (Default)

**Use case**: Initial reconnaissance, public bug bounties

**Allowed**:
- ✓ External scanner-controlled resources
- ✓ Timing analysis
- ✓ Error message collection
- ✓ OOB callbacks to scanner domain

**Forbidden**:
- ✗ Internal IP testing (127.0.0.1, RFC1918)
- ✗ Cloud metadata endpoints
- ✗ Protocol escalation (file://, gopher://)

**Example**:
```bash
ssrfdetect -u "https://example.com/fetch?url=test" -p url --oob-domain oob.example.com
```

### Level 1: Basic

**Use case**: Bug bounty programs, external assessments

**Allowed**:
- ✓ All from Level 0
- ✓ Cloud metadata detection (read-only, safe paths)
- ✓ Public file testing (file:///dev/null, /etc/hostname)
- ✓ Internal network timing inference

**Forbidden**:
- ✗ Actual internal service access
- ✗ Protocol escalation to sensitive protocols
- ✗ Credential exfiltration

**Example**:
```bash
ssrfdetect \
    -u "https://aws-app.example.com/import" \
    -p source \
    --oob-domain oob.example.com \
    --auth-level basic \
    --allow-cloud-metadata \
    -v
```

### Level 2: Full

**Use case**: Authorized red team, internal security assessments

**Allowed**:
- ✓ All from Level 1
- ✓ Internal network enumeration
- ✓ Protocol escalation testing
- ✓ Internal service detection
- ✓ Kubernetes service discovery

**Forbidden**:
- ✗ Service exploitation
- ✗ Data exfiltration
- ✗ State modification

**Example**:
```bash
ssrfdetect \
    -u "https://internal.corp.com/fetch" \
    -p url \
    --oob-domain callbacks.redteam.local \
    --auth-level full \
    --allow-internal \
    --allow-cloud-metadata \
    --allow-protocol-escalation \
    -v
```

### Level 3: Exploit

**Use case**: Controlled testing environments only

**Allowed**:
- ✓ All from Level 2
- ✓ Service manipulation (with rollback)
- ✓ Proof-of-concept exploitation

**Warning**: Use only in isolated test environments.

## Output Formats

### JSON Format

**Use case**: Machine parsing, CI/CD integration, dashboards

```bash
ssrfdetect -u <url> -p <param> --oob-domain <domain> -f json -o report.json
```

**Structure**:
```json
{
  "version": "1.0",
  "generated_at": "2024-01-15T10:30:00Z",
  "scanner": {
    "name": "SSRF Detector",
    "version": "1.0.0"
  },
  "target": {
    "url": "https://example.com/fetch",
    "method": "GET"
  },
  "summary": {
    "total_findings": 1,
    "by_severity": {
      "Critical": 1
    },
    "highest_severity": "Critical",
    "has_cloud_metadata": true
  },
  "findings": [
    {
      "id": "SSRF-1234567890",
      "type": "Cloud_Metadata_SSRF",
      "severity": "Critical",
      "confidence": "High",
      "confidence_score": 95,
      "evidence": [...]
    }
  ]
}
```

### Markdown Format

**Use case**: Bug bounty submissions, documentation

```bash
ssrfdetect -u <url> -p <param> --oob-domain <domain> -f markdown -o report.md
```

**Structure**:
```markdown
# SSRF Detection Report

**Generated**: 2024-01-15T10:30:00Z
**Target**: https://example.com/fetch

## Executive Summary

Total vulnerabilities found: **1**

- 🔴 **Critical**: 1

## Findings

### 1. 🔴 Cloud_Metadata_SSRF

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Confidence** | High (95/100) |

#### Description
[Detailed impact description]

#### Evidence
[Proof of vulnerability]

#### Remediation
[Fix recommendations]
```

### CSV Format

**Use case**: Bulk analysis, spreadsheet import, tracking

```bash
ssrfdetect -u <url> -p <param> --oob-domain <domain> -f csv -o results.csv
```

**Columns**:
```
ID,Type,Severity,Confidence,Confidence Score,Vulnerable Parameter,Impact Summary,Evidence Count,Internal IPs,Cloud Provider,Detected At
```

## Advanced Usage

### Scanning Multiple Parameters

```bash
# Test multiple parameters on same endpoint
for param in url source callback target; do
    ssrfdetect -u "https://example.com/api?${param}=test" \
               -p "$param" \
               --oob-domain oob.example.com \
               -o "report-${param}.json"
done
```

### Integration with Burp Suite

```bash
# 1. Export requests from Burp (Copy as curl)
# 2. Extract URL and parameter
# 3. Run scanner

# Example:
curl 'https://example.com/fetch?url=test' -H 'Cookie: session=abc' > request.txt

# Parse and scan
URL=$(grep -oP "https?://[^']*" request.txt)
ssrfdetect -u "$URL" -p url --oob-domain oob.example.com
```

### CI/CD Integration

**GitHub Actions**:
```yaml
name: SSRF Security Scan

on:
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  ssrf-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SSRF Scan
        run: |
          docker run \
            -v ${{ github.workspace }}/reports:/app/reports \
            -e OOB_DOMAIN=${{ secrets.OOB_DOMAIN }} \
            ssrf-detector \
            -u "${{ secrets.APP_URL }}/fetch" \
            -p url \
            --auth-level basic \
            --allow-cloud-metadata \
            -f json \
            -o /app/reports/scan.json
      
      - name: Check Results
        run: |
          FINDINGS=$(jq '.summary.total_findings' reports/scan.json)
          if [ "$FINDINGS" -gt 0 ]; then
            echo "❌ SSRF vulnerabilities found: $FINDINGS"
            exit 1
          fi
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: ssrf-report
          path: reports/scan.json
```

### Library Usage (Go)

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/yourusername/ssrf-detector/internal/core"
    "github.com/yourusername/ssrf-detector/pkg/ssrfdetect"
)

func main() {
    // Create configuration
    config := core.DefaultConfig()
    config.OOBDomain = "oob.example.com"
    config.AuthLevel = core.AuthLevelBasic
    config.Scope.AllowCloudMetadata = true
    config.Verbose = true
    
    // Create scanner
    scanner, err := ssrfdetect.NewScanner(config)
    if err != nil {
        log.Fatalf("Failed to create scanner: %v", err)
    }
    defer scanner.Close()
    
    // Perform scan
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()
    
    findings, err := scanner.Scan(ctx, "https://example.com/fetch", "url")
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }
    
    // Process findings
    fmt.Printf("Found %d vulnerabilities\n", len(findings))
    for _, finding := range findings {
        fmt.Printf("- %s [%s] Confidence: %s\n",
            finding.Type, finding.Severity, finding.Confidence)
    }
}
```

## Troubleshooting

### Common Issues

#### Issue 1: No OOB Callbacks Received

**Symptoms**: Scan completes but finds no SSRF despite vulnerability existing.

**Possible causes**:
1. OOB domain not configured correctly
2. DNS not resolving
3. Firewall blocking callbacks
4. Application doesn't actually fetch URLs

**Debug steps**:
```bash
# Test DNS resolution
nslookup test.your-oob-domain.com

# Test OOB server
curl http://your-oob-domain.com/test

# Check OOB logs
tail -f /path/to/oob-logs

# Run with verbose mode
ssrfdetect -u <url> -p <param> --oob-domain <domain> -v
```

#### Issue 2: False Positives

**Symptoms**: Scanner reports SSRF but manual validation fails.

**Debug steps**:
```bash
# Check evidence in report
jq '.findings[0].evidence' report.json

# Verify OOB source IP
# Check if source IP belongs to target infrastructure or is CDN/proxy

# Manual validation
curl "https://example.com/fetch?url=http://your-oob-domain.com/manual-test"
# Check OOB logs for callback
```

#### Issue 3: Scan Timeout

**Symptoms**: Scan hangs or times out.

**Possible causes**:
1. Application very slow
2. Network issues
3. Too many baseline samples

**Solutions**:
```bash
# Reduce baseline samples
ssrfdetect ... --baseline-samples 5

# Increase timeout
# Edit config:
http_timeout: "30s"
oob_timeout: "60s"
```

#### Issue 4: Permission Denied for Internal Testing

**Symptoms**: "requires AuthLevelBasic" error when trying to test cloud metadata.

**Solution**:
```bash
# Add authorization flag
ssrfdetect -u <url> -p <param> \
    --oob-domain <domain> \
    --auth-level basic \
    --allow-cloud-metadata
```

## Best Practices

### 1. OOB Domain Setup

**DO**:
- ✓ Use your own domain for production assessments
- ✓ Setup wildcard DNS (*.oob.yourdomain.com)
- ✓ Monitor OOB logs in real-time
- ✓ Use unique identifiers for correlation

**DON'T**:
- ✗ Use public services (interact.sh) for sensitive assessments
- ✗ Share OOB domain across teams (correlation issues)
- ✗ Use predictable OOB URLs

### 2. Scanning Strategy

**DO**:
- ✓ Start with auth-level none (safest)
- ✓ Manually validate all findings
- ✓ Test one parameter at a time initially
- ✓ Use verbose mode for debugging
- ✓ Save reports for evidence

**DON'T**:
- ✗ Scan without authorization
- ✗ Use auth-level full on public bug bounties
- ✗ Ignore false positive checks
- ✗ Scan production during business hours (for internal assessments)

### 3. Bug Bounty Submissions

**DO**:
- ✓ Use markdown format for reports
- ✓ Include full evidence (OOB logs, timing data)
- ✓ Manually validate before submission
- ✓ Explain impact clearly
- ✓ Provide remediation guidance

**DON'T**:
- ✗ Submit without manual validation
- ✗ Include actual credentials in report
- ✗ Test beyond proof-of-concept
- ✗ Submit reflection-only findings

### 4. Performance Optimization

```bash
# For fast scanning
ssrfdetect \
    --baseline-samples 5 \
    --rate-limit 20 \
    --concurrency 10 \
    -u <url> -p <param> --oob-domain <domain>

# For accurate scanning (fewer false positives)
ssrfdetect \
    --baseline-samples 15 \
    --statistical-threshold 4.0 \
    --rate-limit 5 \
    -u <url> -p <param> --oob-domain <domain>
```

### 5. Credential Safety

**NEVER**:
- ✗ Exfiltrate actual IAM credentials
- ✗ Access production databases
- ✗ Fetch /etc/shadow
- ✗ Access Kubernetes secrets

**ALWAYS**:
- ✓ Stop at proof of access
- ✓ Use safe metadata paths (instance-id only)
- ✓ Redact sensitive data in reports
- ✓ Report responsibly

## Performance Tuning

### Scan Speed vs Accuracy

| Profile | Use Case | Settings |
|---------|----------|----------|
| **Fast** | Initial recon | `--baseline-samples 5 --rate-limit 20` |
| **Balanced** | Standard bug bounty | `--baseline-samples 10 --rate-limit 10` |
| **Accurate** | Red team, low FP | `--baseline-samples 15 --statistical-threshold 4.0` |
| **Stealth** | IDS evasion | `--rate-limit 2 --concurrency 1` |

### Resource Usage

**Expected resource consumption**:
- CPU: 10-30% per scan
- Memory: 50-200 MB per scan
- Network: 1-5 Mbps
- Disk: Minimal (<10 MB for reports)

## Support and Resources

### Getting Help

```bash
# Built-in help
ssrfdetect --help

# Verbose debugging
ssrfdetect -u <url> -p <param> --oob-domain <domain> -v 2>&1 | tee debug.log

# Report issues
# Include: debug log, config file, example URL (sanitized)
```

### Additional Documentation

- Architecture: `docs/ARCHITECTURE.md`
- Detection Methodology: `docs/DETECTION_METHODOLOGY.md`
- Bug Bounty Guide: `docs/BUG_BOUNTY_GUIDE.md`
- API Reference: `docs/API_REFERENCE.md`

### Community

- GitHub Issues: Report bugs and feature requests
- Discussions: Share findings and techniques
- Contributing: See CONTRIBUTING.md

## Security Notice

This tool performs active security testing. You are responsible for:
- Obtaining proper authorization
- Respecting scope boundaries
- Following responsible disclosure
- Complying with applicable laws

Unauthorized use may be illegal.
```

---

## File 4: `docs/API_REFERENCE.md`

```markdown
# SSRF Detector - API Reference

## Overview

This document describes the public API for using SSRF Detector as a Go library.

## Package: `pkg/ssrfdetect`

### Scanner

Primary interface for vulnerability scanning.

#### Type Definition

```go
type Scanner struct {
    // private fields
}
```

#### Constructor

```go
func NewScanner(config *core.Config) (*Scanner, error)
```

**Parameters**:
- `config`: Scanner configuration (see Configuration section)

**Returns**:
- `*Scanner`: Initialized scanner instance
- `error`: Configuration validation error

**Example**:
```go
config := core.DefaultConfig()
config.OOBDomain = "oob.example.com"
config.AuthLevel = core.AuthLevelBasic

scanner, err := ssrfdetect.NewScanner(config)
if err != nil {
    log.Fatalf("Scanner initialization failed: %v", err)
}
defer scanner.Close()
```

#### Methods

##### Scan

```go
func (s *Scanner) Scan(ctx context.Context, targetURL string, paramName string) ([]*core.Finding, error)
```

Performs complete SSRF and Open Redirect scan on specified parameter.

**Parameters**:
- `ctx`: Context for cancellation and timeout
- `targetURL`: Full target URL to test
- `paramName`: Parameter name to inject payloads into

**Returns**:
- `[]*core.Finding`: List of confirmed vulnerabilities
- `error`: Scan execution error

**Example**:
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()

findings, err := scanner.Scan(ctx, "https://example.com/fetch?url=test", "url")
if err != nil {
    log.Printf("Scan failed: %v", err)
    return
}

for _, finding := range findings {
    fmt.Printf("Found: %s [%s]\n", finding.Type, finding.Severity)
}
```

##### Close

```go
func (s *Scanner) Close() error
```

Cleanup scanner resources (OOB servers, connections).

**Returns**:
- `error`: Cleanup error (if any)

**Example**:
```go
defer scanner.Close()
```

---

## Package: `internal/core`

Core types and interfaces (importable for advanced usage).

### Configuration

#### Config

```go
type Config struct {
    AuthLevel            AuthorizationLevel
    Scope                ScopeConfig
    OOBDomain            string
    OOBServerURL         string
    OOBTimeout           time.Duration
    HTTPTimeout          time.Duration
    FollowRedirects      bool
    MaxRedirects         int
    UserAgent            string
    RateLimit            int
    Concurrency          int
    BaselineSamples      int
    StatisticalThreshold float64
    MaxInternalTests     int
    DryRun               bool
    Verbose              bool
    ReportFormat         string
    OutputFile           string
}
```

#### Constructor

```go
func DefaultConfig() *Config
```

Returns safe default configuration.

**Example**:
```go
config := core.DefaultConfig()
config.OOBDomain = "oob.example.com"
config.AuthLevel = core.AuthLevelBasic
config.Verbose = true
```

#### Validation

```go
func (c *Config) Validate() error
```

Validates configuration values.

**Returns**:
- `error`: Validation error with details

#### Helper Methods

```go
func (c *Config) CanTestInternal() bool
func (c *Config) CanTestCloudMetadata() bool
func (c *Config) CanEscalateProtocol() bool
```

Check if specific operations are authorized.

---

### Authorization Levels

```go
type AuthorizationLevel int

const (
    AuthLevelNone    AuthorizationLevel = 0
    AuthLevelBasic   AuthorizationLevel = 1
    AuthLevelFull    AuthorizationLevel = 2
    AuthLevelExploit AuthorizationLevel = 3
)
```

**Usage**:
```go
config.AuthLevel = core.AuthLevelBasic
```

---

### Scope Configuration

```go
type ScopeConfig struct {
    InScope                 []string
    OutOfScope              []string
    AllowInternalIPs        bool
    AllowCloudMetadata      bool
    AllowProtocolEscalation bool
}
```

**Example**:
```go
config.Scope = core.ScopeConfig{
    InScope: []string{"*.example.com", "test.com"},
    OutOfScope: []string{"*.internal.example.com"},
    AllowInternalIPs: false,
    AllowCloudMetadata: true,
    AllowProtocolEscalation: false,
}
```

---

### Finding

```go
type Finding struct {
    ID                  string
    Type                VulnerabilityType
    Severity            Severity
    Confidence          ConfidenceLevel
    ConfidenceScore     int
    Target              *Target
    VulnerableParameter string
    Evidence            []Evidence
    ProofOfConcept      string
    Request             string
    Response            string
    Impact              string
    InternalIPsReached  []string
    CloudProvider       string
    DetectedAt          time.Time
    PhaseDetected       DetectionPhase
    Remediation         string
    References          []string
}
```

#### Vulnerability Types

```go
const (
    VulnTypeSSRF               = "SSRF"
    VulnTypeBlindSSRF          = "Blind_SSRF"
    VulnTypeInternalSSRF       = "Internal_SSRF"
    VulnTypeCloudMetadata      = "Cloud_Metadata_SSRF"
    VulnTypeOpenRedirect       = "Open_Redirect"
    VulnTypeRedirectToSSRF     = "Redirect_To_SSRF"
    VulnTypeProtocolEscalation = "Protocol_Escalation"
)
```

#### Severity Levels

```go
const (
    SeverityCritical = "Critical"
    SeverityHigh     = "High"
    SeverityMedium   = "Medium"
    SeverityLow      = "Low"
    SeverityInfo     = "Informational"
)
```

#### Confidence Levels

```go
const (
    ConfidenceHigh   = "High"    // Score ≥ 80
    ConfidenceMedium = "Medium"  // Score 50-79
    ConfidenceLow    = "Low"     // Score 20-49
    ConfidenceNone   = "Invalid" // Score < 20
)
```

---

### Evidence Interface

```go
type Evidence interface {
    Type() EvidenceType
    Score() int
    Description() string
    Data() interface{}
    Timestamp() time.Time
    IsDisqualifying() bool
}
```

#### Evidence Types

```go
const (
    EvidenceOOBCallback        = "oob_callback"
    EvidenceSourceAttribution  = "source_attribution"
    EvidenceTimingAnomaly      = "timing_anomaly"
    EvidenceResponseInclusion  = "response_inclusion"
    EvidenceInternalAccess     = "internal_access"
    EvidenceCloudMetadata      = "cloud_metadata"
    EvidenceErrorMessage       = "error_message"
    EvidenceRedirectFollowing  = "redirect_following"
    EvidenceParserDifferential = "parser_differential"
    EvidenceProtocolEscalation = "protocol_escalation"
    EvidenceReflectionOnly     = "reflection_only"
    EvidenceClientSide         = "client_side"
)
```

---

## Advanced Usage Examples

### Example 1: Custom Configuration

```go
package main

import (
    "context"
    "log"
    "time"

    "ssrf-detector/internal/core"
    "ssrf-detector/pkg/ssrfdetect"
)

func main() {
    config := &core.Config{
        AuthLevel: core.AuthLevelFull,
        OOBDomain: "callbacks.redteam.local",
        OOBTimeout: 60 * time.Second,
        HTTPTimeout: 15 * time.Second,
        FollowRedirects: false,
        MaxRedirects: 5,
        UserAgent: "CustomScanner/1.0",
        RateLimit: 15,
        Concurrency: 10,
        BaselineSamples: 12,
        StatisticalThreshold: 3.5,
        MaxInternalTests: 20,
        Verbose: true,
        ReportFormat: "json",
        Scope: core.ScopeConfig{
            InScope: []string{"*.internal.corp.com"},
            AllowInternalIPs: true,
            AllowCloudMetadata: true,
            AllowProtocolEscalation: true,
        },
    }

    if err := config.Validate(); err != nil {
        log.Fatalf("Invalid config: %v", err)
    }

    scanner, err := ssrfdetect.NewScanner(config)
    if err != nil {
        log.Fatalf("Scanner creation failed: %v", err)
    }
    defer scanner.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()

    findings, err := scanner.Scan(ctx, 
        "https://internal.corp.com/api/webhook?callback_url=test", 
        "callback_url")
    
    if err != nil {
        log.Printf("Scan error: %v", err)
        return
    }

    log.Printf("Scan complete: %d findings", len(findings))
}
```

### Example 2: Batch Scanning

```go
package main

import (
    "bufio"
    "context"
    "fmt"
    "os"
    "sync"
    "time"

    "ssrf-detector/internal/core"
    "ssrf-detector/pkg/ssrfdetect"
)

type ScanTarget struct {
    URL   string
    Param string
}

func main() {
    // Read targets from file
    targets, err := readTargets("targets.txt")
    if err != nil {
        panic(err)
    }

    config := core.DefaultConfig()
    config.OOBDomain = "oob.example.com"
    config.AuthLevel = core.AuthLevelBasic
    config.Scope.AllowCloudMetadata = true

    scanner, err := ssrfdetect.NewScanner(config)
    if err != nil {
        panic(err)
    }
    defer scanner.Close()

    // Parallel scanning with worker pool
    var wg sync.WaitGroup
    results := make(chan []*core.Finding, len(targets))
    semaphore := make(chan struct{}, 5) // 5 concurrent scans

    for _, target := range targets {
        wg.Add(1)
        go func(t ScanTarget) {
            defer wg.Done()
            semaphore <- struct{}{} // Acquire
            defer func() { <-semaphore }() // Release

            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
            defer cancel()

            findings, err := scanner.Scan(ctx, t.URL, t.Param)
            if err != nil {
                fmt.Printf("Error scanning %s: %v\n", t.URL, err)
                return
            }

            if len(findings) > 0 {
                results <- findings
            }
        }(target)
    }

    // Wait and close results
    go func() {
        wg.Wait()
        close(results)
    }()

    // Process results
    totalFindings := 0
    for findings := range results {
        totalFindings += len(findings)
        for _, f := range findings {
            fmt.Printf("[%s] %s - %s (Confidence: %s)\n",
                f.Severity, f.Type, f.Target.URL, f.Confidence)
        }
    }

    fmt.Printf("\nTotal vulnerabilities found: %d\n", totalFindings)
}

func readTargets(filename string) ([]ScanTarget, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var targets []ScanTarget
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        // Format: URL|param
        parts := strings.Split(line, "|")
        if len(parts) == 2 {
            targets = append(targets, ScanTarget{
                URL:   parts[0],
                Param: parts[1],
            })
        }
    }

    return targets, scanner.Err()
}
```

### Example 3: Custom Reporting

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "time"

    "ssrf-detector/internal/core"
    "ssrf-detector/pkg/ssrfdetect"
)

type CustomReport struct {
    ScanTime    time.Time            `json:"scan_time"`
    Target      string               `json:"target"`
    Findings    []SimplifiedFinding  `json:"findings"`
    Summary     Summary              `json:"summary"`
}

type SimplifiedFinding struct {
    Type       string   `json:"type"`
    Severity   string   `json:"severity"`
    Confidence int      `json:"confidence"`
    Evidence   []string `json:"evidence"`
}

type Summary struct {
    Total    int            `json:"total"`
    Critical int            `json:"critical"`
    High     int            `json:"high"`
}