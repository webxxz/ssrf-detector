package core

import (
    "fmt"
    "time"
)

// OOBCallbackEvidence represents evidence from out-of-band callback
type OOBCallbackEvidence struct {
    Callback      *OOBCallback
    CorrelationID string
    Verified      bool
    timestamp     time.Time
}

func (e *OOBCallbackEvidence) Type() EvidenceType {
    return EvidenceOOBCallback
}

func (e *OOBCallbackEvidence) Score() int {
    score := 40 // Base score for OOB callback
    
    // Bonus for verified target infrastructure
    if e.Callback.IsTargetInfrastructure {
        score += 20
    }
    
    // Penalty for CDN/proxy
    if e.Callback.IsCDN {
        score -= 30
    }
    
    // Disqualify if from researcher
    if e.Callback.IsResearcher {
        return -100 // Disqualifying
    }
    
    return score
}

func (e *OOBCallbackEvidence) Description() string {
    return fmt.Sprintf("OOB callback received from %s at %s (Protocol: %s, UA: %s)",
        e.Callback.SourceIP,
        e.Callback.Timestamp.Format(time.RFC3339),
        e.Callback.Protocol,
        e.Callback.UserAgent,
    )
}

func (e *OOBCallbackEvidence) Data() interface{} {
    return e.Callback
}

func (e *OOBCallbackEvidence) Timestamp() time.Time {
    return e.timestamp
}

func (e *OOBCallbackEvidence) IsDisqualifying() bool {
    return e.Callback.IsResearcher || (!e.Callback.IsTargetInfrastructure && !e.Verified)
}

// TimingAnomalyEvidence represents statistically significant timing differences
type TimingAnomalyEvidence struct {
    BaselineMean  time.Duration
    BaselineStdDev time.Duration
    TestDuration  time.Duration
    ZScore        float64
    Samples       int
    TestType      string
    timestamp     time.Time
}

func (e *TimingAnomalyEvidence) Type() EvidenceType {
    return EvidenceTimingAnomaly
}

func (e *TimingAnomalyEvidence) Score() int {
    // Weak evidence, only counts with high statistical significance
    if e.Samples < 10 {
        return -25 // Insufficient samples
    }
    
    absZ := e.ZScore
    if absZ < 0 {
        absZ = -absZ
    }
    
    if absZ > 5.0 {
        return 20
    } else if absZ > 3.0 {
        return 15
    }
    
    return 0 // Not significant enough
}

func (e *TimingAnomalyEvidence) Description() string {
    return fmt.Sprintf("Timing anomaly: %.2fms (baseline: %.2fms±%.2fms, Z=%.2f, n=%d)",
        float64(e.TestDuration.Milliseconds()),
        float64(e.BaselineMean.Milliseconds()),
        float64(e.BaselineStdDev.Milliseconds()),
        e.ZScore,
        e.Samples,
    )
}

func (e *TimingAnomalyEvidence) Data() interface{} {
    return map[string]interface{}{
        "baseline_mean":   e.BaselineMean,
        "baseline_stddev": e.BaselineStdDev,
        "test_duration":   e.TestDuration,
        "z_score":         e.ZScore,
        "samples":         e.Samples,
        "test_type":       e.TestType,
    }
}

func (e *TimingAnomalyEvidence) Timestamp() time.Time {
    return e.timestamp
}

func (e *TimingAnomalyEvidence) IsDisqualifying() bool {
    return false
}

// ResponseInclusionEvidence shows external content in response
type ResponseInclusionEvidence struct {
    ExternalContent string
    ResponseExcerpt string
    IsDynamic       bool  // Content changes when source changes
    UniqueMarker    string
    timestamp       time.Time
}

func (e *ResponseInclusionEvidence) Type() EvidenceType {
    return EvidenceResponseInclusion
}

func (e *ResponseInclusionEvidence) Score() int {
    if !e.IsDynamic {
        return -100 // Likely reflection, disqualifying
    }
    return 30 // Dynamic content confirms fetch
}

func (e *ResponseInclusionEvidence) Description() string {
    return fmt.Sprintf("Response includes external content (marker: %s, dynamic: %v)",
        e.UniqueMarker, e.IsDynamic)
}

func (e *ResponseInclusionEvidence) Data() interface{} {
    return map[string]interface{}{
        "marker":   e.UniqueMarker,
        "dynamic":  e.IsDynamic,
        "excerpt":  e.ResponseExcerpt,
    }
}

func (e *ResponseInclusionEvidence) Timestamp() time.Time {
    return e.timestamp
}

func (e *ResponseInclusionEvidence) IsDisqualifying() bool {
    return !e.IsDynamic
}

// InternalAccessEvidence proves access to internal network
type InternalAccessEvidence struct {
    InternalIP      string
    ServiceResponse string
    ServiceType     string  // Redis, MySQL, HTTP, etc.
    ErrorMessage    string  // "Connection refused", etc.
    timestamp       time.Time
}

func (e *InternalAccessEvidence) Type() EvidenceType {
    return EvidenceInternalAccess
}

func (e *InternalAccessEvidence) Score() int {
    if e.ServiceResponse != "" {
        return 45 // Strong evidence - got actual response
    }
    if e.ErrorMessage != "" && 
       (e.ErrorMessage == "Connection refused" || e.ErrorMessage == "Connection timeout") {
        return 35 // Medium evidence - IP reached
    }
    return 20
}

func (e *InternalAccessEvidence) Description() string {
    if e.ServiceResponse != "" {
        return fmt.Sprintf("Internal service response from %s (type: %s)",
            e.InternalIP, e.ServiceType)
    }
    return fmt.Sprintf("Internal IP %s reached (error: %s)",
        e.InternalIP, e.ErrorMessage)
}

func (e *InternalAccessEvidence) Data() interface{} {
    return map[string]interface{}{
        "internal_ip":     e.InternalIP,
        "service_type":    e.ServiceType,
        "service_response": e.ServiceResponse,
        "error_message":   e.ErrorMessage,
    }
}

func (e *InternalAccessEvidence) Timestamp() time.Time {
    return e.timestamp
}

func (e *InternalAccessEvidence) IsDisqualifying() bool {
    return false
}

// CloudMetadataEvidence proves cloud metadata access
type CloudMetadataEvidence struct {
    Provider      string  // AWS, GCP, Azure
    Endpoint      string
    MetadataPath  string
    DataRetrieved string  // Instance ID, etc. (not credentials)
    IMDSVersion   string  // v1, v2
    timestamp     time.Time
}

func (e *CloudMetadataEvidence) Type() EvidenceType {
    return EvidenceCloudMetadata
}

func (e *CloudMetadataEvidence) Score() int {
    return 50 // Critical evidence
}

func (e *CloudMetadataEvidence) Description() string {
    return fmt.Sprintf("%s metadata accessible (endpoint: %s, version: %s, data: %s)",
        e.Provider, e.Endpoint, e.IMDSVersion, e.DataRetrieved)
}

func (e *CloudMetadataEvidence) Data() interface{} {
    return map[string]interface{}{
        "provider":       e.Provider,
        "endpoint":       e.Endpoint,
        "path":           e.MetadataPath,
        "data_retrieved": e.DataRetrieved,
        "imds_version":   e.IMDSVersion,
    }
}

func (e *CloudMetadataEvidence) Timestamp() time.Time {
    return e.timestamp
}

func (e *CloudMetadataEvidence) IsDisqualifying() bool {
    return false
}

// ReflectionOnlyEvidence is disqualifying evidence
type ReflectionOnlyEvidence struct {
    InputURL      string
    OutputURL     string
    NoOOBCallback bool
    NoTimingDiff  bool
    timestamp     time.Time
}

func (e *ReflectionOnlyEvidence) Type() EvidenceType {
    return EvidenceReflectionOnly
}

func (e *ReflectionOnlyEvidence) Score() int {
    return -100 // Disqualifying
}

func (e *ReflectionOnlyEvidence) Description() string {
    return fmt.Sprintf("Input reflected without execution (input: %s, no OOB, no timing anomaly)",
        e.InputURL)
}

func (e *ReflectionOnlyEvidence) Data() interface{} {
    return map[string]interface{}{
        "input":         e.InputURL,
        "output":        e.OutputURL,
        "no_oob":        e.NoOOBCallback,
        "no_timing":     e.NoTimingDiff,
    }
}

func (e *ReflectionOnlyEvidence) Timestamp() time.Time {
    return e.timestamp
}

func (e *ReflectionOnlyEvidence) IsDisqualifying() bool {
    return true
}