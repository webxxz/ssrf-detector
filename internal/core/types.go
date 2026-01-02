// Package core defines the fundamental types and interfaces for the SSRF detector.
package core

import (
    "context"
    "net/http"
    "net/url"
    "time"
)

// AuthorizationLevel defines what testing is permitted
type AuthorizationLevel int

const (
    // AuthLevelNone - Only external scanner-controlled resources
    AuthLevelNone AuthorizationLevel = iota
    
    // AuthLevelBasic - Bug bounty / external assessment
    // Allows: cloud metadata detection (read-only), public file testing
    AuthLevelBasic
    
    // AuthLevelFull - Red team / internal assessment
    // Allows: internal service enumeration, protocol escalation
    AuthLevelFull
    
    // AuthLevelExploit - Controlled environment only
    // Allows: service manipulation with rollback
    AuthLevelExploit
)

// VulnerabilityType categorizes the finding
type VulnerabilityType string

const (
    VulnTypeSSRF             VulnerabilityType = "SSRF"
    VulnTypeBlindSSRF        VulnerabilityType = "Blind_SSRF"
    VulnTypeInternalSSRF     VulnerabilityType = "Internal_SSRF"
    VulnTypeCloudMetadata    VulnerabilityType = "Cloud_Metadata_SSRF"
    VulnTypeOpenRedirect     VulnerabilityType = "Open_Redirect"
    VulnTypeRedirectToSSRF   VulnerabilityType = "Redirect_To_SSRF"
    VulnTypeProtocolEscalation VulnerabilityType = "Protocol_Escalation"
)

// Severity levels following industry standards
type Severity string

const (
    SeverityCritical Severity = "Critical"
    SeverityHigh     Severity = "High"
    SeverityMedium   Severity = "Medium"
    SeverityLow      Severity = "Low"
    SeverityInfo     Severity = "Informational"
)

// ConfidenceLevel represents evidence quality
type ConfidenceLevel string

const (
    ConfidenceHigh   ConfidenceLevel = "High"     // ≥80 score
    ConfidenceMedium ConfidenceLevel = "Medium"   // 50-79 score
    ConfidenceLow    ConfidenceLevel = "Low"      // 20-49 score
    ConfidenceNone   ConfidenceLevel = "Invalid"  // <20 score
)

// Target represents a URL to be tested
type Target struct {
    URL            *url.URL
    Method         string
    Headers        http.Header
    Body           []byte
    InjectionPoint InjectionPoint
    
    // Metadata
    OriginalRequest string
    Tags           []string
    Priority       int
}

// InjectionPoint identifies where to inject test payloads
type InjectionPoint struct {
    Type     InjectionType
    Name     string          // Parameter name, header name, etc.
    Position int             // Position in body/path if applicable
    Context  PayloadContext  // JSON, XML, URL-encoded, etc.
}

// InjectionType categorizes injection locations
type InjectionType string

const (
    InjectionQuery     InjectionType = "query_parameter"
    InjectionBody      InjectionType = "body_parameter"
    InjectionHeader    InjectionType = "header"
    InjectionPath      InjectionType = "path_segment"
    InjectionJSON      InjectionType = "json_value"
    InjectionXML       InjectionType = "xml_value"
    InjectionMultipart InjectionType = "multipart_field"
)

// PayloadContext describes the encoding/parsing context
type PayloadContext string

const (
    ContextRaw        PayloadContext = "raw"
    ContextURLEncoded PayloadContext = "url_encoded"
    ContextJSON       PayloadContext = "json"
    ContextXML        PayloadContext = "xml"
    ContextBase64     PayloadContext = "base64"
)

// DetectionPhase represents stages in the detection workflow
type DetectionPhase string

const (
    PhaseReachability      DetectionPhase = "reachability"
    PhaseCapability        DetectionPhase = "capability_discovery"
    PhaseFetchAnalysis     DetectionPhase = "fetch_analysis"
    PhaseRedirectAnalysis  DetectionPhase = "redirect_analysis"
    PhaseTrustBoundary     DetectionPhase = "trust_boundary"
    PhaseParserDifferential DetectionPhase = "parser_differential"
    PhaseEncodingBoundary  DetectionPhase = "encoding_boundary"
    PhaseProtocolEscalation DetectionPhase = "protocol_escalation"
    PhaseInternalAccess    DetectionPhase = "internal_access"
    PhaseVerification      DetectionPhase = "verification"
)

// PhaseResult contains the outcome of a detection phase
type PhaseResult struct {
    Phase         DetectionPhase
    Success       bool
    Evidence      []Evidence
    NextPhase     DetectionPhase
    ShouldStop    bool
    Error         error
    Duration      time.Duration
    Metadata      map[string]interface{}
}

// DetectionEngine interface for phase-based detection
type DetectionEngine interface {
    // Execute runs the detection phase
    Execute(ctx context.Context, target *Target, state *ScanState) (*PhaseResult, error)
    
    // Name returns the phase name
    Name() DetectionPhase
    
    // RequiredAuthLevel returns minimum authorization needed
    RequiredAuthLevel() AuthorizationLevel
    
    // DependsOn returns required previous phases
    DependsOn() []DetectionPhase
}

// ScanState maintains state across detection phases
type ScanState struct {
    Target             *Target
    Config             *Config
    
    // Phase results
    PhaseResults       map[DetectionPhase]*PhaseResult
    
    // Accumulated evidence
    Evidence           []Evidence
    
    // Fingerprints
    ClientFingerprint  *HTTPClientFingerprint
    ValidatorFingerprint *ValidatorFingerprint
    
    // Capabilities detected
    Capabilities       map[string]bool
    
    // Baseline measurements
    Baseline           *Baseline
    
    // OOB tracking
    OOBManager         OOBManager
    
    // Timing data
    TimingData         *TimingAnalysis
    
    // Metadata
    StartTime          time.Time
    Metadata           map[string]interface{}
}

// Baseline contains normal behavior measurements
type Baseline struct {
    ResponseTime       time.Duration
    ResponseTimeStdDev time.Duration
    ResponseSize       int
    ResponseHash       string
    StatusCode         int
    Headers            http.Header
    
    // Statistical data
    Samples            int
    TimingSamples      []time.Duration
}

// HTTPClientFingerprint identifies the server's HTTP client
type HTTPClientFingerprint struct {
    UserAgent        string
    Library          string          // e.g., "Python-urllib", "curl", "Go-http-client"
    Version          string
    TLSFingerprint   string          // JA3 hash
    Headers          http.Header
    Capabilities     []string        // Supported features
    ProtocolSupport  []string        // http, https, ftp, file, etc.
}

// ValidatorFingerprint describes validation behavior
type ValidatorFingerprint struct {
    ValidationLayer   ValidationLayer
    BlockedRanges     []string        // IP ranges blocked
    AllowedSchemes    []string
    ValidationTiming  time.Duration   // How long validation takes
    ErrorPatterns     []string
    EncodingHandling  EncodingBehavior
}

// ValidationLayer indicates where validation occurs
type ValidationLayer string

const (
    ValidationString  ValidationLayer = "string_based"
    ValidationDNS     ValidationLayer = "dns_based"
    ValidationIP      ValidationLayer = "ip_based"
    ValidationSocket  ValidationLayer = "socket_based"
)

// EncodingBehavior describes decoding characteristics
type EncodingBehavior struct {
    URLDecodeStages   int
    JSONDecodeFirst   bool
    Base64Support     bool
    NullByteHandling  string
}

// Config holds scanner configuration
type Config struct {
    // Authorization
    AuthLevel         AuthorizationLevel
    Scope             ScopeConfig
    
    // OOB configuration
    OOBDomain         string
    OOBServerURL      string
    OOBTimeout        time.Duration
    
    // HTTP client settings
    HTTPTimeout       time.Duration
    FollowRedirects   bool
    MaxRedirects      int
    UserAgent         string
    
    // Rate limiting
    RateLimit         int  // requests per second
    Concurrency       int
    
    // Detection settings
    BaselineSamples   int
    StatisticalThreshold float64  // Sigma threshold for timing
    
    // Safety
    MaxInternalTests  int  // Limit internal IP testing
    DryRun            bool // Report what would be tested
    
    // Output
    Verbose           bool
    ReportFormat      string
    OutputFile        string
}

// ScopeConfig defines testing boundaries
type ScopeConfig struct {
    InScope           []string  // Domain/IP patterns
    OutOfScope        []string
    AllowInternalIPs  bool
    AllowCloudMetadata bool
    AllowProtocolEscalation bool
}

// Evidence represents a piece of proof for a vulnerability
type Evidence interface {
    // Type returns the evidence type
    Type() EvidenceType
    
    // Score returns the confidence points this evidence contributes
    Score() int
    
    // Description returns human-readable description
    Description() string
    
    // Data returns the raw evidence data
    Data() interface{}
    
    // Timestamp returns when evidence was collected
    Timestamp() time.Time
    
    // IsDisqualifying returns true if this evidence invalidates the finding
    IsDisqualifying() bool
}

// EvidenceType categorizes evidence
type EvidenceType string

const (
    EvidenceOOBCallback        EvidenceType = "oob_callback"
    EvidenceSourceAttribution  EvidenceType = "source_attribution"
    EvidenceTimingAnomaly      EvidenceType = "timing_anomaly"
    EvidenceResponseInclusion  EvidenceType = "response_inclusion"
    EvidenceInternalAccess     EvidenceType = "internal_access"
    EvidenceCloudMetadata      EvidenceType = "cloud_metadata"
    EvidenceErrorMessage       EvidenceType = "error_message"
    EvidenceRedirectFollowing  EvidenceType = "redirect_following"
    EvidenceParserDifferential EvidenceType = "parser_differential"
    EvidenceReflectionOnly     EvidenceType = "reflection_only"  // Disqualifying
    EvidenceClientSide         EvidenceType = "client_side"      // Disqualifying
)

// Finding represents a detected vulnerability
type Finding struct {
    ID                string
    Type              VulnerabilityType
    Severity          Severity
    Confidence        ConfidenceLevel
    ConfidenceScore   int
    
    // Target information
    Target            *Target
    VulnerableParameter string
    
    // Evidence
    Evidence          []Evidence
    
    // Proof
    ProofOfConcept    string
    Request           string
    Response          string
    
    // Impact
    Impact            string
    InternalIPsReached []string
    CloudProvider     string
    
    // Metadata
    DetectedAt        time.Time
    PhaseDetected     DetectionPhase
    
    // Remediation
    Remediation       string
    References        []string
}

// OOBManager handles out-of-band callback tracking
type OOBManager interface {
    // GenerateIdentifier creates a unique correlation ID
    GenerateIdentifier(target *Target, testType string) (string, error)
    
    // BuildURL constructs an OOB URL with identifier
    BuildURL(identifier string, path string) (string, error)
    
    // WaitForCallback waits for a callback with the identifier
    WaitForCallback(ctx context.Context, identifier string, timeout time.Duration) (*OOBCallback, error)
    
    // CheckCallback checks if callback was received (non-blocking)
    CheckCallback(identifier string) (*OOBCallback, bool)
    
    // GetCallbacks returns all callbacks for an identifier
    GetCallbacks(identifier string) []*OOBCallback
}

// OOBCallback represents an out-of-band interaction
type OOBCallback struct {
    Identifier    string
    Protocol      string  // DNS, HTTP, HTTPS
    SourceIP      string
    SourcePort    int
    Timestamp     time.Time
    
    // HTTP-specific
    Method        string
    Path          string
    Headers       http.Header
    UserAgent     string
    Body          []byte
    
    // DNS-specific
    QueryType     string
    QueryName     string
    
    // Attribution
    IsTargetInfrastructure bool
    IsCDN                  bool
    IsResearcher          bool
    PTRRecord             string
}

// TimingAnalysis holds statistical timing data
type TimingAnalysis struct {
    Baseline          *TimingStats
    Tests             map[string]*TimingStats
}

// TimingStats contains statistical measurements
type TimingStats struct {
    Samples       []time.Duration
    Mean          time.Duration
    StdDev        time.Duration
    Min           time.Duration
    Max           time.Duration
    Count         int
}

// HTTPClient interface abstracts HTTP operations
type HTTPClient interface {
    // Do executes an HTTP request
    Do(ctx context.Context, req *http.Request) (*Response, error)
    
    // DoWithTiming executes request and returns detailed timing
    DoWithTiming(ctx context.Context, req *http.Request) (*Response, *RequestTiming, error)
}

// Response wraps http.Response with additional metadata
type Response struct {
    *http.Response
    
    // Timing information
    DNSLookup     time.Duration
    TCPConnection time.Duration
    TLSHandshake  time.Duration
    ServerProcessing time.Duration
    ContentTransfer time.Duration
    Total         time.Duration
    
    // Body (captured)
    BodyBytes     []byte
    BodyHash      string
    
    // Metadata
    FinalURL      string  // After redirects
    RedirectChain []*RedirectHop
}

// RequestTiming contains detailed timing breakdown
type RequestTiming struct {
    Start            time.Time
    DNSStart         time.Time
    DNSDone          time.Time
    ConnectStart     time.Time
    ConnectDone      time.Time
    TLSStart         time.Time
    TLSDone          time.Time
    RequestSent      time.Time
    ResponseStart    time.Time
    ResponseDone     time.Time
    End              time.Time
}

// RedirectHop represents one step in a redirect chain
type RedirectHop struct {
    URL           string
    StatusCode    int
    Location      string
    Timestamp     time.Time
}

// Reporter generates reports from findings
type Reporter interface {
    // Generate creates a report from findings
    Generate(findings []*Finding, state *ScanState) ([]byte, error)
    
    // Format returns the report format (JSON, Markdown, etc.)
    Format() string
}