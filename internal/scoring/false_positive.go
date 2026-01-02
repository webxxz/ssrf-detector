package scoring

import (
	"fmt"

	"ssrf-detector/internal/core"
)

// FalsePositiveChecker validates findings to eliminate false positives
type FalsePositiveChecker struct {
	config *core.Config
}

// NewFalsePositiveChecker creates a new false positive checker
func NewFalsePositiveChecker(config *core.Config) *FalsePositiveChecker {
	return &FalsePositiveChecker{
		config: config,
	}
}

// Check validates a finding and returns error if it's a false positive
func (c *FalsePositiveChecker) Check(finding *core.Finding, state *core.ScanState) error {
	// Rule 1: Must have non-disqualifying evidence
	if err := c.checkEvidenceQuality(finding); err != nil {
		return err
	}

	// Rule 2: OOB callbacks must be properly attributed
	if err := c.checkOOBAttribution(finding); err != nil {
		return err
	}

	// Rule 3: Timing evidence must be statistically significant
	if err := c.checkTimingValidity(finding); err != nil {
		return err
	}

	// Rule 4: Must not be reflection-only
	if err := c.checkNotReflection(finding); err != nil {
		return err
	}

	// Rule 5: Client-side behavior excluded
	if err := c.checkNotClientSide(finding); err != nil {
		return err
	}

	return nil
}

// checkEvidenceQuality validates evidence quality
func (c *FalsePositiveChecker) checkEvidenceQuality(finding *core.Finding) error {
	if len(finding.Evidence) == 0 {
		return fmt.Errorf("no evidence provided")
	}

	// Check for disqualifying evidence
	for _, ev := range finding.Evidence {
		if ev.IsDisqualifying() {
			return fmt.Errorf("disqualifying evidence found: %s", ev.Description())
		}
	}

	// Require at least one strong evidence type
	hasStrongEvidence := false

	for _, ev := range finding.Evidence {
		switch ev.Type() {
		case core.EvidenceOOBCallback,
			core.EvidenceInternalAccess,
			core.EvidenceCloudMetadata:
			hasStrongEvidence = true
		}
	}

	if !hasStrongEvidence && finding.Confidence != core.ConfidenceHigh {
		// If no strong evidence, require high confidence from multiple weak evidences
		if finding.ConfidenceScore < 70 {
			return fmt.Errorf("insufficient evidence quality (score: %d)", finding.ConfidenceScore)
		}
	}

	return nil
}

// checkOOBAttribution validates OOB callback attribution
func (c *FalsePositiveChecker) checkOOBAttribution(finding *core.Finding) error {
	hasOOB := false

	for _, ev := range finding.Evidence {
		if oobEv, ok := ev.(*core.OOBCallbackEvidence); ok {
			hasOOB = true

			// Check source attribution
			if oobEv.Callback.IsResearcher {
				return fmt.Errorf("OOB callback from researcher IP (client-side)")
			}

			if oobEv.Callback.IsCDN {
				return fmt.Errorf("OOB callback from CDN (not target infrastructure)")
			}

			if !oobEv.Callback.IsTargetInfrastructure && !oobEv.Verified {
				return fmt.Errorf("OOB callback source not verified as target infrastructure")
			}
		}
	}

	// For SSRF findings, OOB is highly preferred (but not always required)
	if finding.Type == core.VulnTypeSSRF && !hasOOB {
		// Check if we have alternative strong evidence
		hasAlternative := false
		for _, ev := range finding.Evidence {
			if ev.Type() == core.EvidenceInternalAccess || ev.Type() == core.EvidenceCloudMetadata {
				hasAlternative = true
			}
		}

		if !hasAlternative {
			return fmt.Errorf("SSRF finding requires OOB callback or internal access evidence")
		}
	}

	return nil
}

// checkTimingValidity validates timing-based evidence
func (c *FalsePositiveChecker) checkTimingValidity(finding *core.Finding) error {
	for _, ev := range finding.Evidence {
		if timingEv, ok := ev.(*core.TimingAnomalyEvidence); ok {
			// Check sample size
			if timingEv.Samples < c.config.BaselineSamples {
				return fmt.Errorf("timing evidence has insufficient samples: %d (required: %d)",
					timingEv.Samples, c.config.BaselineSamples)
			}

			// Check statistical significance
			absZ := timingEv.ZScore
			if absZ < 0 {
				absZ = -absZ
			}

			if absZ < c.config.StatisticalThreshold {
				return fmt.Errorf("timing difference not statistically significant: Z=%.2f (threshold: %.2f)",
					absZ, c.config.StatisticalThreshold)
			}
		}
	}

	return nil
}

// checkNotReflection ensures finding is not just reflection
func (c *FalsePositiveChecker) checkNotReflection(finding *core.Finding) error {
	// Check for reflection-only evidence
	for _, ev := range finding.Evidence {
		if ev.Type() == core.EvidenceReflectionOnly {
			return fmt.Errorf("finding is reflection-only, not SSRF")
		}
	}

	// Additional check: if ResponseInclusion evidence exists, must be dynamic
	for _, ev := range finding.Evidence {
		if respEv, ok := ev.(*core.ResponseInclusionEvidence); ok {
			if !respEv.IsDynamic {
				return fmt.Errorf("response includes input but content is not dynamic (likely reflection)")
			}
		}
	}

	return nil
}

// checkNotClientSide ensures it's not client-side behavior
func (c *FalsePositiveChecker) checkNotClientSide(finding *core.Finding) error {
	// Check all OOB callbacks
	for _, ev := range finding.Evidence {
		if oobEv, ok := ev.(*core.OOBCallbackEvidence); ok {
			// Check User-Agent
			if oobEv.Callback.UserAgent != "" {
				ua := oobEv.Callback.UserAgent

				// Browser User-Agents indicate client-side
				if isBrowserUserAgent(ua) {
					return fmt.Errorf("OOB callback has browser User-Agent (client-side redirect)")
				}
			}
		}
	}

	// For open redirect, ensure it's not just client-side navigation
	if finding.Type == core.VulnTypeOpenRedirect {
		// Open redirect is expected to be client-side, so this is OK
		// But check if it's being misclassified as SSRF

		for _, ev := range finding.Evidence {
			if ev.Type() == core.EvidenceOOBCallback {
				if oobEv, ok := ev.(*core.OOBCallbackEvidence); ok {
					if oobEv.Callback.IsTargetInfrastructure {
					}
				}
			}
		}

		// Open redirect without server-side evidence is OK
		return nil
	}

	return nil
}

// isBrowserUserAgent checks if User-Agent indicates a browser
func isBrowserUserAgent(ua string) bool {
	browserIndicators := []string{
		"Mozilla/5.0",
		"Chrome/",
		"Safari/",
		"Firefox/",
		"Edge/",
		"Opera/",
	}

	for _, indicator := range browserIndicators {
		if contains(ua, indicator) {
			return true
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
