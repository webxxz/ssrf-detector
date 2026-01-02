# Documentation Files

## File 1: `docs/ARCHITECTURE.md`

```markdown
# SSRF Detector - Architecture Documentation

## Overview

The SSRF Detector is designed as a modular, phase-based detection system that systematically identifies Server-Side Request Forgery and Open Redirect vulnerabilities through evidence-based analysis.

## Design Principles

### 1. Safety-First Architecture

```
Authorization Levels (Enforced at Runtime)
├── Level 0 (None) - External resources only
├── Level 1 (Basic) - Bug bounty safe operations
├── Level 2 (Full) - Red team authorized operations
└── Level 3 (Exploit) - Controlled environment only
```

**Key Safety Features**:
- All phases check authorization before execution
- Scope enforcement at configuration level
- Dry-run mode for testing
- Automatic termination on dangerous operations without auth

### 2. Evidence-Based Detection

**No vulnerability is reported without proof**:
- OOB callback verification
- Statistical timing analysis
- Response fingerprinting
- Multi-evidence correlation

### 3. False Positive Elimination

```
Evidence Collection → Scoring → False Positive Check → Report
                         ↓              ↓
                   Confidence      Disqualifying
                   Calculation     Evidence Filter
```

## System Architecture

### Layer 1: Core Types (`internal/core/`)

**Purpose**: Define all interfaces, types, and contracts.

```
core/
├── types.go      - All type definitions
├── evidence.go   - Evidence implementations
└── config.go     - Configuration management
```

**Key Interfaces**:

```go
DetectionEngine interface
├── Execute() - Run detection phase
├── Name() - Phase identifier
├── RequiredAuthLevel() - Safety check
└── DependsOn() - Phase dependencies

OOBManager interface
├── GenerateIdentifier() - Create unique correlation ID
├── BuildURL() - Construct OOB URL
├── WaitForCallback() - Block until callback
└── CheckCallback() - Non-blocking check

HTTPClient interface
├── Do() - Execute HTTP request
└── DoWithTiming() - Execute with detailed timing
```

### Layer 2: OOB Management (`internal/oob/`)

**Purpose**: Handle out-of-band callback tracking and attribution.

```
oob/
├── manager.go      - Core OOB management
├── attribution.go  - Source IP attribution
├── server.go       - HTTP/DNS callback servers
└── oob_test.go     - Test suite
```

**Attribution Flow**:

```
Callback Received
    ↓
Extract Source IP
    ↓
Check Against Known Sources
    ├── Target Infrastructure? → Mark verified
    ├── CDN IP? → Mark as CDN (potential FP)
    ├── Researcher IP? → Mark as client-side (FP)
    └── Unknown → Perform PTR lookup
         ↓
    Check PTR for patterns
         ├── Contains "cloudflare" → CDN
         ├── Contains target domain → Verified
         └── Unknown → Requires manual review
```

### Layer 3: Detection Engines (`internal/detection/`)

**Purpose**: Implement phase-based vulnerability detection.

```
detection/
├── engine.go                  - Pipeline orchestration
├── reachability.go           - Phase 0: Baseline
├── capability.go             - Phase 1: Capability discovery
├── fetch_analysis.go         - Phase 2A: SSRF analysis
├── redirect_analysis.go      - Phase 2B: Redirect analysis
├── trust_boundary.go         - Phase 3: Trust mapping
├── parser_differential.go    - Phase 4: Parser bugs
├── encoding_boundary.go      - Phase 5: Encoding issues
├── protocol_escalation.go    - Phase 6: Protocol testing
├── internal_access.go        - Phase 7: Internal network
└── verification.go           - Phase 8: FP elimination
```

**Phase Execution Model**:

```go
type PhaseResult struct {
    Success    bool              // Phase completed
    Evidence   []Evidence        // Collected evidence
    NextPhase  DetectionPhase    // Where to go next
    ShouldStop bool              // Terminate scan
    Error      error             // Failure reason
    Metadata   map[string]any    // Phase-specific data
}
```

**Phase Dependencies**:

```
Phase 0: Reachability
    ↓
Phase 1: Capability Discovery
    ↓
    ├─→ Phase 2A: Fetch Analysis (if fetch capability)
    │       ↓
    │   Phase 3: Trust Boundary
    │       ↓
    │   Phase 4: Parser Differential
    │       ↓
    │   Phase 5: Encoding Boundary
    │       ↓
    │   Phase 6: Protocol Escalation
    │       ↓
    │   Phase 7: Internal Access
    │
    └─→ Phase 2B: Redirect Analysis (if redirect capability)
            ↓
        (May escalate to Phase 7)
    ↓
Phase 8: Verification
```

### Layer 4: HTTP Client (`internal/http/`)

**Purpose**: Instrumented HTTP client with detailed timing.

```
http/
├── client.go       - HTTP client implementation
└── client_test.go  - Test suite
```

**Timing Instrumentation**:

```
Request Lifecycle Timing:
├── DNS Resolution
├── TCP Connection
├── TLS Handshake
├── Request Sent
├── First Byte Received
├── Content Transfer
└── Total Time

Used for:
- Blind SSRF detection
- Internal vs external differentiation
- Timeout detection
- Performance analysis
```

### Layer 5: Scoring System (`internal/scoring/`)

**Purpose**: Calculate confidence scores and severity.

```
scoring/
├── scorer.go           - Confidence calculation
├── false_positive.go   - FP elimination
└── analysis.go         - Statistical analysis
```

**Scoring Algorithm**:

```
Evidence Points:
├── OOB Callback: +40
├── Source Verified: +20
├── Internal Access: +45
├── Cloud Metadata: +50
├── Timing Anomaly (>5σ): +20
├── Response Inclusion (dynamic): +30
└── ...

Penalty Points:
├── Reflection Only: -100 (disqualifying)
├── Client-Side: -100 (disqualifying)
├── CDN Source: -30
├── Insufficient Samples: -25
└── ...

Confidence Level:
├── Score ≥ 80: HIGH
├── Score 50-79: MEDIUM
├── Score 20-49: LOW
└── Score < 20: INVALID
```

### Layer 6: Reporting (`internal/report/`)

**Purpose**: Generate machine and human-readable reports.

```
report/
├── json.go      - JSON output
├── markdown.go  - Bug bounty reports
└── csv.go       - Bulk analysis
```

## Data Flow

### Complete Scan Flow

```
1. Input Processing
   ├── Parse target URL
   ├── Identify injection points
   └── Validate configuration

2. OOB Initialization
   ├── Start callback servers
   └── Setup correlation tracking

3. Detection Pipeline
   ├── Execute phases sequentially
   ├── Collect evidence at each phase
   └── Update scan state

4. Evidence Correlation
   ├── Aggregate all evidence
   ├── Check for disqualifying evidence
   └── Calculate confidence

5. Finding Generation
   ├── Classify vulnerability type
   ├── Calculate severity
   └── Build finding object

6. False Positive Check
   ├── Validate OOB attribution
   ├── Check statistical significance
   ├── Eliminate reflection-only
   └── Verify reproducibility

7. Report Generation
   ├── Format findings
   ├── Include evidence
   └── Output to file/stdout
```

## State Management

### ScanState Structure

```go
type ScanState struct {
    // Immutable
    Target   *Target
    Config   *Config
    
    // Accumulated during scan
    PhaseResults  map[DetectionPhase]*PhaseResult
    Evidence      []Evidence
    
    // Fingerprints
    ClientFingerprint    *HTTPClientFingerprint
    ValidatorFingerprint *ValidatorFingerprint
    
    // Baseline
    Baseline   *Baseline
    
    // Capabilities discovered
    Capabilities  map[string]bool
    
    // OOB tracking
    OOBManager    OOBManager
    
    // Metadata
    StartTime  time.Time
    Metadata   map[string]interface{}
}
```

**State Transitions**:

```
Initial State
    ↓
Phase 0 adds: Baseline
    ↓
Phase 1 adds: Capabilities
    ↓
Phase 2A adds: ClientFingerprint
    ↓
Phase 3 adds: ValidatorFingerprint
    ↓
Phases 4-7 add: Evidence
    ↓
Phase 8: Validates evidence
    ↓
Final State → Finding
```

## Concurrency Model

### Goroutine Usage

```
Main Thread
    ├── Pipeline Orchestrator (sequential phase execution)
    │
    ├── OOB Server
    │   ├── HTTP Handler (goroutine per request)
    │   └── DNS Handler (goroutine per query)
    │
    └── HTTP Client
        └── Connection Pool (managed by net/http)
```

**Synchronization**:
- OOB callbacks: Channel-based signaling
- State updates: Sequential (no locks needed)
- HTTP requests: Connection pooling (built-in)

### Context Propagation

```go
Context Hierarchy:
    Root Context (main)
        ↓
    Scan Context (with timeout)
        ↓
    Phase Context (inherited)
        ↓
    Request Context (per HTTP request)
        ↓
    OOB Wait Context (per callback wait)
```

## Error Handling Strategy

### Error Categories

1. **Fatal Errors** (terminate scan)
   - Configuration validation failure
   - OOB manager initialization failure
   - Network completely unreachable

2. **Phase Errors** (skip phase, continue)
   - Individual phase failure
   - Timeout on specific test
   - Authorization insufficient

3. **Warnings** (log, continue)
   - OOB timeout (expected for some tests)
   - Baseline variance high
   - Attribution ambiguous

### Error Propagation

```
Error occurs in Phase X
    ↓
Captured in PhaseResult.Error
    ↓
Pipeline checks error
    ↓
    ├── Fatal? → Return error, stop scan
    ├── Recoverable? → Log, continue to next phase
    └── Expected? → Log as info, continue
```

## Performance Characteristics

### Resource Usage

**Memory**:
- Per scan: ~10-50 MB
- Baseline samples: ~1 KB each
- Evidence storage: ~1-5 KB per evidence
- OOB callback storage: ~2 KB per callback

**Network**:
- Baseline: 10-20 requests
- Full scan: 50-200 requests
- OOB callbacks: Variable (1-10 expected)

**Time**:
- Fast scan (external only): 30-60 seconds
- Full scan (with internal): 2-5 minutes
- Cloud metadata detection: +30 seconds

### Optimization Techniques

1. **Connection Pooling**
   - Reuse TCP connections
   - Reduce TLS handshake overhead

2. **Request Deduplication**
   - Cache baseline responses
   - Avoid redundant tests

3. **Early Termination**
   - Stop on disqualifying evidence
   - Skip phases when capabilities not detected

4. **Parallel Phase Execution** (future)
   - Independent phases can run concurrently
   - Evidence aggregation at the end

## Security Considerations

### Scanner Security

**Input Validation**:
- Target URL sanitization
- Parameter name validation
- Config value bounds checking

**Output Sanitization**:
- Report generation escapes user input
- Prevents injection in reports
- Safe file writing

**Scope Enforcement**:
- In-scope/out-of-scope checking
- Authorization level gates
- Network boundary respect

### Operational Security

**Credentials**:
- Never exfiltrate actual credentials
- Stop at proof of access
- Redact sensitive data in reports

**Logging**:
- No sensitive data in logs
- OOB callbacks sanitized
- Error messages safe

## Extension Points

### Adding New Detection Phase

```go
// 1. Implement DetectionEngine interface
type NewPhaseEngine struct {
    config     *core.Config
    httpClient core.HTTPClient
    oobManager core.OOBManager
}

func (e *NewPhaseEngine) Execute(ctx context.Context, target *core.Target, state *core.ScanState) (*core.PhaseResult, error) {
    // Implementation
}

// 2. Register in pipeline
func NewPipeline(...) {
    engines := []core.DetectionEngine{
        // ... existing engines
        NewNewPhaseEngine(config, httpClient, oobManager),
    }
}
```

### Adding New Evidence Type

```go
// 1. Define evidence type constant
const EvidenceNewType EvidenceType = "new_type"

// 2. Implement Evidence interface
type NewEvidence struct {
    // fields
}

func (e *NewEvidence) Type() EvidenceType { return EvidenceNewType }
func (e *NewEvidence) Score() int { /* scoring logic */ }
// ... other methods

// 3. Use in detection phases
result.Evidence = append(result.Evidence, &NewEvidence{...})
```

### Adding New Report Format

```go
// 1. Implement Reporter interface
type NewFormatReporter struct {
    config *core.Config
}

func (r *NewFormatReporter) Format() string { return "newformat" }
func (r *NewFormatReporter) Generate(findings []*core.Finding, state *core.ScanState) ([]byte, error) {
    // Format logic
}

// 2. Register in CLI
switch config.ReportFormat {
case "newformat":
    reporter = report.NewNewFormatReporter(config)
}
```

## Testing Strategy

### Unit Tests
- Each package has `*_test.go`
- Mock interfaces for isolation
- Table-driven tests for edge cases

### Integration Tests
- `test/integration/` with `+build integration` tag
- Real HTTP servers (httptest)
- End-to-end workflow validation

### Test Coverage Targets
- Core types: 80%+
- Detection engines: 70%+
- OOB manager: 80%+
- Overall: 75%+

## Deployment Models

### Standalone Binary
```bash
./ssrfdetect -u <url> --oob-domain <domain>
```

### Docker Container
```bash
docker run -e OOB_DOMAIN=oob.example.com ssrf-detector -u <url>
```

### Library Integration
```go
import "ssrf-detector/pkg/ssrfdetect"

scanner, _ := ssrfdetect.NewScanner(config)
findings, _ := scanner.Scan(ctx, targetURL, paramName)
```

### CI/CD Integration
```yaml
# .github/workflows/security-scan.yml
- name: SSRF Scan
  run: |
    ssrfdetect -u ${{ env.APP_URL }} \
               --oob-domain ${{ secrets.OOB_DOMAIN }} \
               -o scan-results.json
```

## Future Enhancements

### Planned Features

1. **Distributed Scanning**
   - Multiple scanner nodes
   - Centralized OOB server
   - Result aggregation

2. **Machine Learning Integration**
   - Pattern recognition for injection points
   - Anomaly detection
   - False positive reduction

3. **Advanced Protocol Support**
   - WebSocket SSRF
   - GraphQL SSRF
   - gRPC SSRF

4. **Cloud-Native Features**
   - Kubernetes operator
   - Cloud provider native integrations
   - Terraform scanner

## Conclusion

This architecture prioritizes:
- **Safety**: Authorization-gated operations
- **Accuracy**: Evidence-based detection
- **Scalability**: Modular, extensible design
- **Maintainability**: Clear interfaces, documented code
- **Performance**: Efficient resource usage

The phase-based approach ensures systematic coverage while the evidence-based model minimizes false positives, making it suitable for production security assessments.
```

---

## File 2: `docs/DETECTION_METHODOLOGY.md`

```markdown
# SSRF Detection Methodology

## Introduction

This document explains the scientific methodology behind SSRF and Open Redirect detection, focusing on **why** techniques work, not just **what** payloads to use.

## Core Detection Principles

### 1. Observable Side Effects

**Principle**: SSRF creates observable side effects that differ from reflection.

```
Reflection:
User Input → Application → Response (input echoed)
Observable: Response content only

SSRF:
User Input → Application → External Fetch → Response
Observable: Network activity, timing, external content
```

**What we measure**:
- Out-of-band callbacks (direct observation)
- Timing anomalies (indirect observation)
- Response content changes (content observation)
- Error message patterns (failure observation)

### 2. Statistical Significance

**Principle**: Single measurements are unreliable; statistical analysis required.

**Baseline Establishment**:
```
Collect n samples (n ≥ 10)
Calculate μ (mean) and σ (standard deviation)
Threshold: |test - μ| > 3σ (99.7% confidence)
```

**Why this matters**:
- Network timing has natural variance
- Server load affects response times
- Single anomaly could be random
- Statistical validation eliminates false positives

**Example**:
```
Baseline: 150ms ± 20ms (10 samples)
Test 1: 180ms → Z = (180-150)/20 = 1.5 (not significant)
Test 2: 215ms → Z = (215-150)/20 = 3.25 (significant at 3σ)
Test 3: 12ms → Z = (12-150)/20 = -6.9 (highly significant)
```

### 3. Multi-Evidence Correlation

**Principle**: No single signal is sufficient; require multiple corroborating evidences.

**Evidence Hierarchy**:
```
Tier 1 (Strong):
- OOB callback from verified source
- Cloud metadata response
- Internal service fingerprint

Tier 2 (Medium):
- Timing anomaly (>5σ)
- Dynamic content inclusion
- Parser differential confirmed

Tier 3 (Weak):
- Reflection with timing
- Error messages
- Header influence
```

**Correlation Rules**:
- 1 × Tier 1 = Report
- 1 × Tier 1 + 1 × Tier 2 = High confidence
- 2 × Tier 2 = Medium confidence
- 3 × Tier 3 = Low confidence (manual review)

## Detection Phases Explained

### Phase 0: Reachability & Baseline

**Purpose**: Establish ground truth for comparison.

**Methodology**:
1. Send n legitimate requests (default: 10)
2. Measure: timing, response size, status code
3. Calculate statistical baseline
4. Identify error handling patterns

**Why multiple samples?**
- Eliminate cache effects
- Account for load variance
- Detect rate limiting
- Establish reliable baseline

**Output**:
```go
Baseline {
    Mean: 145ms
    StdDev: 12ms
    StatusCode: 200
    BodyHash: "abc123..."
}
```

### Phase 1: Capability Discovery

**Purpose**: Determine if endpoint has fetch or redirect capabilities.

**Tests**:

**1.1 External Fetch Test**
```
Inject: http://scanner.oob.domain/capability-test
Monitor: OOB callback, timing, response content

Decision Tree:
├── OOB callback received
│   ├── Before response → Server-side fetch (sync)
│   └── After response → Possible client-side or async
├── Response includes external content → Fetch with inclusion
├── Timing > baseline + network_time → Possible blind fetch
└── No signals → No fetch capability
```

**Why this matters**: Different capabilities require different detection strategies.

**1.2 Redirect Detection**
```
Inject: http://scanner.oob.domain/redirect-test
Monitor: HTTP 3xx, Location header, JS/meta redirects

Classification:
├── HTTP 302/301 → Standard redirect
├── window.location → JavaScript redirect
├── <meta refresh> → Meta redirect
└── OOB + redirect → Server-side redirect (escalation risk)
```

### Phase 2A: Fetch Analysis (SSRF Path)

**Purpose**: Characterize HTTP client behavior.

**2A.1 Protocol Support Discovery**
```
Test: http:// (baseline)
Test: https://
Test: HTTP:// (case variation)

Goal: Identify which schemes are accepted
Method: Monitor OOB callbacks for each scheme
```

**2A.2 Client Fingerprinting**
```
From OOB callback headers:
User-Agent: Python-urllib/3.9 → Python application
User-Agent: curl/7.68.0 → curl-based
User-Agent: Go-http-client/1.1 → Go application

Fingerprint enables:
- Predict protocol support
- Identify parser behavior
- Understand limitations
```

**2A.3 Port Restriction Discovery**
```
Test: :80, :443, :8080, :22, :6379

Results map allowed ports:
Allowed: [80, 443, 8080]
Blocked: [22, 6379]

Insight: Blacklist exists for dangerous ports
```

### Phase 3: Trust Boundary Discovery

**Purpose**: Identify WHERE validation occurs in the request pipeline.

**3.1 Validation Layer Detection**

```
Test Sequence:
1. Invalid URL format: "not-a-url-xyz"
   → Fast reject (<50ms) → String-based validation
   
2. Non-existent domain: "nonexistent-xyz.invalid"
   → 5s timeout → DNS-based validation
   
3. Valid domain resolving to internal IP
   → Post-DNS validation → IP-based validation
   
4. Connection to blocked port
   → Post-connection check → Socket-based validation
```

**Why layer matters**:
- String-based: Can bypass with encoding
- DNS-based: Vulnerable to DNS rebinding
- IP-based: Need IP encoding bypasses
- Socket-based: Hardest to bypass

**3.2 DNS Resolution Trust Test**

```
Methodology:
1. First request: scanner.oob.domain → public IP
2. Application resolves DNS
3. Application makes request
4. Second request: same domain
5. Check if application re-resolves or caches

If caches without re-validation:
→ Vulnerable to DNS rebinding attack
```

### Phase 4: Parser Differential Discovery

**Purpose**: Find differences between validator and HTTP client parsing.

**4.1 Authority Section Parsing**

```
Test: http://allowed.com@evil.com/

Parser A (validator):
- Sees "allowed.com@evil.com" as hostname → Allowed

Parser B (HTTP client):
- Sees "allowed.com" as userinfo
- Sees "evil.com" as hostname → Connects to evil.com

Result: SSRF via parser differential
```

**4.2 IP Representation Testing**

```
Using scanner IP (203.0.113.50):

Test 1: http://203.0.113.50/ → Baseline
Test 2: http://3405803826/ (decimal) → OOB callback?
Test 3: http://0xCB007132/ (hex) → OOB callback?
Test 4: http://0313.0.0161.062/ (octal) → OOB callback?

If baseline works but validator blocks internal IPs:
→ Test same encodings with 127.0.0.1
→ If callback received: Parser differential confirmed
```

**Why safe testing first**:
- Never test internal IPs during discovery
- Use scanner's public IP
- Infer internal bypass from external behavior

### Phase 5: Encoding Boundary Discovery

**Purpose**: Find encoding/decoding stage mismatches.

**5.1 Decode Stage Mapping**

```
Progressive encoding test:

Marker: "A" (ASCII 65, URL-encoded: %41)

Test 1: /path-A → Callback path: /path-A
  Result: No decoding (or decoded elsewhere)

Test 2: /path-%41 → Callback path: /path-A
  Result: One decode stage

Test 3: /path-%2541 → Callback path: /path-%41
  Result: One decode stage (first % decoded)

Test 4: /path-%2541 → Callback path: /path-A
  Result: Two decode stages

Conclusion: Exactly N decode stages in pipeline
```

**5.2 Validation Boundary Detection**

```
Known blocked value: 127.0.0.1

Test 1: http://127.0.0.1 → Blocked (baseline)
Test 2: http://127.0.0.%31 → Response?

If allowed:
→ Validator sees "127.0.0.%31" (pre-decode)
→ Validator doesn't recognize as localhost
→ Client decodes %31 → 1
→ Client connects to 127.0.0.1
→ BYPASS via encoding boundary
```

### Phase 6: Protocol Escalation

**Purpose**: Test non-HTTP protocol support (requires authorization).

**6.1 Safe Protocol Detection**

```
Test invalid protocol first:
invalid-protocol://test → Error message

Analyze error:
- "Invalid URL" → Generic rejection
- "Protocol 'invalid-protocol' not supported" → Parser recognizes schemes

Test file:// with safe path:
file:///dev/null → Response?

Result analysis:
- Empty response + fast timing → file:// works
- Error "Protocol not supported" → Blocked
- Timeout → Attempted but failed
```

**Why start with /dev/null**:
- Safe to read (always empty)
- Exists on all Unix systems
- Proves file:// capability without sensitive access

### Phase 7: Internal Access Detection

**Purpose**: Detect internal network reachability (requires authorization).

**7.1 Localhost Detection**

```
Test: http://127.0.0.1/

Signal Analysis:
├── "Connection refused" → Port reached (localhost accessible)
├── Timeout → Attempted but no service
├── Fast reject → Validation blocked
└── Service response → CRITICAL: Internal service accessible

Timing analysis:
├── Response < 50ms → Local (very fast)
├── Response ~150ms → External (baseline)
└── Response ~5s → Timeout (attempted)
```

**7.2 Cloud Metadata Detection**

```
Pre-detection: Identify cloud provider
- Check target IP range (WHOIS)
- Check response headers (X-Amz-*, Server: EC2ws)
- Check error messages

Test appropriate endpoint:
AWS: http://169.254.169.254/latest/meta-data/instance-id
GCP: http://metadata.google.internal/...
Azure: http://169.254.169.254/metadata/...

Response analysis:
├── Instance ID format → AWS confirmed
├── JSON with vmId → Azure confirmed
├── Numeric ID → GCP confirmed
└── Fast timing (<50ms) → Link-local speed

STOP at instance-id:
- Do NOT fetch credentials
- Proof of access is sufficient
- Ethical boundary
```

### Phase 8: Verification & FP Elimination

**Purpose**: Ensure all findings are genuine.

**8.1 OOB Attribution Verification**

```
Callback received:
├── Source IP → WHOIS lookup
├── PTR record → Reverse DNS
├── User-Agent → Library fingerprint
└── Timing → Correlation check

Verification Rules:
✓ Source IP in target netblock → Verified
✓ PTR contains target domain → Verified
✓ User-Agent is server library → Likely server-side
✗ Source is researcher IP → CLIENT-SIDE (discard)
✗ Source is CDN → False positive (discard)
✗ User-Agent is browser → CLIENT-SIDE (discard)
```

**8.2 Timing Verification**

```
Timing evidence requirements:
- n ≥ 10 samples
- |Z-score| ≥ 3
- Reproducible (≥2 trials)

Statistical validation:
Z = (test_time - baseline_mean) / baseline_stddev

Acceptance:
|Z| ≥ 5.0 → High confidence
|Z| ≥ 3.0 → Medium confidence
|Z| < 3.0 → Insufficient (discard)
```

**8.3 Reflection Elimination**

```
Reflection Test:
1. Inject unique marker: UNIQUE-XYZ-12345
2. Check response contains marker
3. Change external content
4. Re-inject same URL
5. Check if response updated

If response unchanged:
→ Reflection only (discard)

If response updated:
→ True fetch (keep)
```

**8.4 Reproducibility Test**

```
Repeat finding 3 times:
- Same parameter
- Same payload
- Fresh requests

Success criteria:
≥2/3 successes → Reproducible (report)
<2/3 successes → Flaky (manual review)
0/3 successes → False positive (discard)
```

## Advanced Techniques

### DNS Rebinding Detection

**Theory**: Validator resolves DNS at T0, client resolves at T1.

```
Setup:
- attacker.com initially resolves to 1.2.3.4 (public)
- TTL = 1 second
- After 2 seconds, resolves to 127.0.0.1

Test flow:
T0: Application validates attacker.com → 1.2.3.4 (allowed)
T1: Delay in application processing
T2: Application fetches attacker.com → 127.0.0.1 (SSRF)

Detection:
- Can't directly test (requires DNS control)
- Infer vulnerability if:
  - Application caches DNS results
  - No re-validation before fetch
  - Long processing time between validation and fetch
```

### HTTP Request Smuggling → SSRF

**Theory**: CRLF injection in URL creates HTTP request splitting.

```
Payload: http://127.0.0.1:6379/%0d%0aGET%20/admin%0d%0a

Validator sees: URL to 127.0.0.1 with path
HTTP client sends:
  GET /%0d%0aGET%20/admin%0d%0a HTTP/1.1
  Host: 127.0.0.1:6379

Server interprets as TWO requests:
  Request 1: GET / HTTP/1.1
  Request 2: GET /admin HTTP/1.1

Detection signals:
- Double responses
- Timing suggests multiple requests
- Error messages from second request
```

### Cache Poisoning → SSRF

**Theory**: Cached responses with attacker-controlled URLs fetched later.

```
Attack flow:
1. Attacker poisons cache entry
2. Cache contains: {key: "logo", value: "http://attacker.com/logo.png"}
3. Victim requests logo
4. Application fetches from cache → SSRF

Detection:
- Delayed OOB callbacks (after cache population)
- Timing: First request slow, second fast (cached)
- Multiple OOB callbacks from same parameter
```

## Severity Calculation

### Impact Assessment Matrix

```
CRITICAL:
- Cloud metadata credentials accessible
- file:// protocol with arbitrary read
- Internal service RCE (gopher → Redis)
- K8s service account token accessible

HIGH:
- Internal network accessible (RFC1918)
- Cloud metadata readable (non-creds)
- Protocol escalation (limited)
- Blind SSRF to internal services

MEDIUM:
- External SSRF (validated)
- Blind SSRF (external only)
- Open Redirect with token leakage potential

LOW:
- Open Redirect (client-side only)
- Restrictive SSRF (port/protocol limited)
```

### Confidence Scoring

```
Formula:
Confidence = Σ(evidence_scores) - Σ(penalty_scores)

Thresholds:
≥80: HIGH (auto-report)
50-79: MEDIUM (review)
20-49: LOW (likely FP)
<20: INVALID (discard)
```

## Common False Positives

### FP Pattern 1: CDN Prefetch

```
Observation: OOB callback received
Source IP: Cloudflare range
User-Agent: CloudFlare-AlwaysOnline

Root cause: CDN prefetches URLs to check availability
NOT SSRF: Target application didn't make request

Detection: Check source IP against CDN ranges
```

### FP Pattern 2: Browser Prefetch

```
Observation: OOB callback received
Source IP: Researcher IP
User-Agent: Mozilla/5.0...

Root cause: Researcher's browser prefetched link
NOT SSRF: Client-side behavior

Detection: Source IP + browser User-Agent
```

### FP Pattern 3: Reflection Timing

```
Observation: Timing difference detected
Response contains input URL

Root cause: Complex reflection (database lookup, etc.)
NOT SSRF: No actual fetch occurred

Detection: Content analysis shows only reflection
```

## Conclusion

This methodology prioritizes:

1. **Scientific Rigor**: Statistical validation, not guesswork
2. **Evidence-Based**: Multiple signals required
3. **Safe Testing**: External resources first, infer internal
4. **Low False Positives**: Strict verification before reporting
5. **Ethical Boundaries**: Proof of access, not exploitation

The phase-based approach ensures systematic coverage while avoiding common pitfalls in automated SSRF detection.
```