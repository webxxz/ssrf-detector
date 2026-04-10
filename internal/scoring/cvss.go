package scoring

import (
	"fmt"
	"math"
	"strings"

	"ssrf-detector/internal/core"
)

// CVSSVector stores CVSS v3.1 base metrics.
type CVSSVector struct {
	AV string
	AC string
	PR string
	UI string
	S  string
	C  string
	I  string
	A  string
}

// ScoredFinding is a scoring-oriented view of a finding for CVSS derivation.
type ScoredFinding struct {
	Finding *core.Finding

	RequiresWAF bool

	AuthRequired  bool
	AdminRequired bool

	ReachesAWSMetadata bool
	ReachesRedisPort   bool

	CredentialTheftChain bool
	BlindOnly            bool

	RCEChain              bool
	InternalWritePossible bool

	DoSChainDetected bool
}

// ComputeCVSS calculates CVSS v3.1 base score and vector for SSRF findings.
func ComputeCVSS(finding *ScoredFinding) (score float64, vectorString string) {
	if finding == nil {
		return 0, ""
	}

	v := deriveVector(finding)
	score = computeBaseScore(v)
	vectorString = fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		v.AV, v.AC, v.PR, v.UI, v.S, v.C, v.I, v.A)
	return score, vectorString
}

func deriveVector(f *ScoredFinding) CVSSVector {
	reachesAWS := f.ReachesAWSMetadata || inferReachesAWSMetadata(f.Finding)
	reachesRedis := f.ReachesRedisPort || inferReachesRedisPort(f.Finding)
	credentialChain := f.CredentialTheftChain || inferCredentialTheftChain(f.Finding)
	rceChain := f.RCEChain || inferRCEChain(f.Finding)
	dosChain := f.DoSChainDetected || inferDoSChain(f.Finding)
	internalAccess := inferInternalAccess(f.Finding)
	blindOnly := f.BlindOnly || inferBlindOnly(f.Finding)

	ac := "L"
	if f.RequiresWAF || f.AuthRequired || f.AdminRequired {
		ac = "H"
	}

	pr := "N"
	if f.AdminRequired {
		pr = "H"
	} else if f.AuthRequired {
		pr = "L"
	}

	s := "U"
	if reachesAWS || reachesRedis {
		s = "C"
	}

	c := "L"
	switch {
	// Precedence follows impact severity: credential-theft chain dominates blind-only hints.
	case credentialChain:
		c = "H"
	case blindOnly:
		c = "N"
	case internalAccess:
		c = "L"
	}

	i := "N"
	switch {
	case rceChain:
		i = "H"
	case f.InternalWritePossible:
		i = "L"
	}

	a := "L"
	if dosChain {
		a = "H"
	}

	return CVSSVector{
		AV: "N",
		AC: ac,
		PR: pr,
		UI: "N",
		S:  s,
		C:  c,
		I:  i,
		A:  a,
	}
}

func computeBaseScore(v CVSSVector) float64 {
	avWeights := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acWeights := map[string]float64{"L": 0.77, "H": 0.44}
	uiWeights := map[string]float64{"N": 0.85, "R": 0.62}
	impactWeights := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}

	prWeightsU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWeightsC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}

	av, ok := avWeights[v.AV]
	if !ok {
		return 0
	}
	ac, ok := acWeights[v.AC]
	if !ok {
		return 0
	}
	ui, ok := uiWeights[v.UI]
	if !ok {
		return 0
	}
	c, ok := impactWeights[v.C]
	if !ok {
		return 0
	}
	i, ok := impactWeights[v.I]
	if !ok {
		return 0
	}
	a, ok := impactWeights[v.A]
	if !ok {
		return 0
	}

	pr := 0.0
	switch v.S {
	case "U":
		var ok bool
		pr, ok = prWeightsU[v.PR]
		if !ok {
			return 0
		}
	case "C":
		var ok bool
		pr, ok = prWeightsC[v.PR]
		if !ok {
			return 0
		}
	default:
		return 0
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	impact := 0.0
	if v.S == "U" {
		impact = 6.42 * iss
	} else {
		// CVSS v3.1 base metric formula for Scope Changed (Specification v3.1, Section 2).
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0
	}

	baseScore := 0.0
	if v.S == "U" {
		baseScore = roundUp1Decimal(math.Min(impact+exploitability, 10))
	} else {
		baseScore = roundUp1Decimal(math.Min(1.08*(impact+exploitability), 10))
	}
	return baseScore
}

func roundUp1Decimal(x float64) float64 {
	return math.Ceil(x*10.0) / 10.0
}

func inferReachesAWSMetadata(f *core.Finding) bool {
	if f == nil {
		return false
	}
	if f.Type == core.VulnTypeCloudMetadata && strings.EqualFold(f.CloudProvider, "AWS") {
		return true
	}
	for _, ev := range f.Evidence {
		if cloudEv, ok := ev.(*core.CloudMetadataEvidence); ok {
			if strings.EqualFold(cloudEv.Provider, "AWS") {
				return true
			}
		}
	}
	return false
}

func inferReachesRedisPort(f *core.Finding) bool {
	if f == nil {
		return false
	}
	for _, ev := range f.Evidence {
		if internalEv, ok := ev.(*core.InternalAccessEvidence); ok {
			if strings.EqualFold(internalEv.ServiceType, "redis") || strings.Contains(strings.ToLower(internalEv.ServiceResponse), "redis") {
				return true
			}
		}
	}
	for _, chain := range f.AttackChains {
		title := strings.ToLower(chain.Title)
		if strings.Contains(title, "redis") {
			return true
		}
	}
	return false
}

func inferCredentialTheftChain(f *core.Finding) bool {
	if f == nil {
		return false
	}
	for _, chain := range f.AttackChains {
		title := strings.ToLower(chain.Title)
		if strings.Contains(title, "credential theft") {
			return true
		}
	}
	// AWS metadata access is treated as credential-theft-capable by default because
	// IMDS role paths can expose temporary IAM credentials in common SSRF chains.
	return inferReachesAWSMetadata(f)
}

func inferRCEChain(f *core.Finding) bool {
	if f == nil {
		return false
	}
	for _, chain := range f.AttackChains {
		title := strings.ToLower(chain.Title)
		if strings.Contains(title, "rce") || strings.Contains(title, "command execution") {
			return true
		}
	}
	return false
}

func inferDoSChain(f *core.Finding) bool {
	if f == nil {
		return false
	}
	for _, chain := range f.AttackChains {
		title := strings.ToLower(chain.Title)
		if strings.Contains(title, "dos") || strings.Contains(title, "denial of service") {
			return true
		}
	}
	return false
}

func inferInternalAccess(f *core.Finding) bool {
	if f == nil {
		return false
	}
	if len(f.InternalIPsReached) > 0 {
		return true
	}
	switch f.Type {
	case core.VulnTypeInternalSSRF, core.VulnTypeCloudMetadata, core.VulnTypeProtocolEscalation:
		return true
	}
	for _, ev := range f.Evidence {
		if ev.Type() == core.EvidenceInternalAccess || ev.Type() == core.EvidenceCloudMetadata {
			return true
		}
	}
	return false
}

func inferBlindOnly(f *core.Finding) bool {
	if f == nil {
		return false
	}
	if f.Type != core.VulnTypeBlindSSRF {
		return false
	}
	return !inferInternalAccess(f) && !inferReachesAWSMetadata(f) && !inferReachesRedisPort(f) && !inferRCEChain(f)
}
