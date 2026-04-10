package chain

import (
	"strings"

	"ssrf-detector/internal/core"
)

// ReasonChains derives plausible SSRF escalation chains from an accepted finding.
func ReasonChains(finding *core.Finding) []core.AttackChain {
	chains := make([]core.AttackChain, 0)
	if finding == nil {
		return chains
	}

	if reachesAWSMetadata(finding) {
		chains = append(chains, core.AttackChain{
			Title: "SSRF → AWS credential theft",
			Steps: []string{
				"SSRF to 169.254.169.254",
				"Extract IAM role name from /meta-data/iam/security-credentials/",
				"Fetch credentials JSON → AccessKeyId + SecretAccessKey + Token",
				"Use credentials for account enumeration and privilege abuse",
			},
			CVSS:   9.8,
			Impact: "Potential AWS account compromise",
		})
	}

	if reachesRedisViaSSRF(finding) {
		chains = append(chains, core.AttackChain{
			Title: "SSRF → Redis RCE (gopher path)",
			Steps: []string{
				"SSRF to Redis service via loopback/internal path",
				"Protocol escalation to gopher:// payload shaping",
				"Manipulate Redis configuration or writable paths",
				"Achieve command execution under Redis context",
			},
			CVSS:   9.0,
			Impact: "Remote code execution potential",
		})
	}

	if finding.Type == core.VulnTypeRedirectToSSRF {
		chains = append(chains, core.AttackChain{
			Title: "Open Redirect → SSRF allowlist bypass",
			Steps: []string{
				"Direct SSRF blocked by allowlist",
				"Open redirect found on trusted/allowlisted domain",
				"Server follows trusted redirect to internal destination",
				"Allowlist bypass enables internal/cloud metadata access",
			},
			CVSS:   8.5,
			Impact: "Allowlist bypass to internal resources",
		})
	}

	return chains
}

func reachesAWSMetadata(finding *core.Finding) bool {
	if finding.Type == core.VulnTypeCloudMetadata && strings.EqualFold(finding.CloudProvider, "AWS") {
		return true
	}
	for _, ev := range finding.Evidence {
		if cloudEv, ok := ev.(*core.CloudMetadataEvidence); ok {
			if strings.EqualFold(cloudEv.Provider, "AWS") {
				return true
			}
		}
	}
	return false
}

func reachesRedisViaSSRF(finding *core.Finding) bool {
	if finding.Type == core.VulnTypeProtocolEscalation {
		for _, ev := range finding.Evidence {
			if internalEv, ok := ev.(*core.InternalAccessEvidence); ok {
				if strings.EqualFold(internalEv.ServiceType, "redis") || strings.Contains(strings.ToLower(internalEv.ServiceResponse), "redis") {
					return true
				}
			}
		}
	}
	return false
}
