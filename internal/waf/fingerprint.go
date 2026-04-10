package waf

import (
	"io"
	"net/http"
	"strings"
)

type WAFVendor string

const (
	WAFCloudflare  WAFVendor = "cloudflare"
	WAFAkamai      WAFVendor = "akamai"
	WAFAwsWAF      WAFVendor = "aws-waf"
	WAFModSecurity WAFVendor = "modsecurity"
	WAFNone        WAFVendor = "none"
)

// FingerprintWAF attempts to identify common WAF vendors from a response.
func FingerprintWAF(resp *http.Response) WAFVendor {
	if resp == nil {
		return WAFNone
	}
	if resp.Header.Get("CF-Ray") != "" {
		return WAFCloudflare
	}
	if resp.Header.Get("X-Check-Cacheable") != "" {
		return WAFAkamai
	}
	if resp.Header.Get("X-Amzn-Requestid") != "" || resp.Header.Get("X-Amz-Cf-Id") != "" {
		return WAFAwsWAF
	}

	server := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(server, "apache") && resp.StatusCode == http.StatusForbidden && resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return WAFNone
		}
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		body := strings.ToLower(string(bodyBytes))
		if strings.Contains(body, "mod_security") || strings.Contains(body, "modsecurity") {
			return WAFModSecurity
		}
	}
	return WAFNone
}
