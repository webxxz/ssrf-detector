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
	if resp.Header.Get("cf-ray") != "" {
		return WAFCloudflare
	}
	if resp.Header.Get("x-check-cacheable") != "" {
		return WAFAkamai
	}
	if resp.Header.Get("x-amzn-requestid") != "" || resp.Header.Get("x-amz-cf-id") != "" {
		return WAFAwsWAF
	}

	server := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(server, "apache") && resp.StatusCode == http.StatusForbidden && resp.Body != nil {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		body := strings.ToLower(string(bodyBytes))
		if strings.Contains(body, "mod_security") || strings.Contains(body, "modsecurity") {
			return WAFModSecurity
		}
	}
	return WAFNone
}
