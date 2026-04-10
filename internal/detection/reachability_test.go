package detection

import (
	"net/http"
	"testing"

	"ssrf-detector/internal/core"
)

func TestInferBackendHints(t *testing.T) {
	resp := &core.Response{
		Response: &http.Response{
			Header: http.Header{
				"Set-Cookie": []string{"JSESSIONID=abc"},
				"Server":     []string{"Apache Tomcat/9.0"},
			},
		},
	}

	hints := inferBackendHints(resp)
	if len(hints) == 0 {
		t.Fatal("expected backend hints")
	}
	if hints[0] != "java" {
		t.Fatalf("expected java hint, got %v", hints)
	}
}

func TestInferEdgeAndCloudHints(t *testing.T) {
	resp := &core.Response{
		Response: &http.Response{
			Header: http.Header{
				"Server": []string{"cloudflare"},
				"Via":    []string{"1.1 varnish"},
			},
		},
		BodyBytes: []byte("x-amz-request-id"),
	}

	edge := inferEdgeHints(resp)
	if !edge["reverse_proxy"] {
		t.Fatal("expected reverse_proxy hint")
	}
	if !edge["cloudflare"] {
		t.Fatal("expected cloudflare hint")
	}

	cloud := inferCloudHints(resp)
	if len(cloud) == 0 || cloud[0] != "aws" {
		t.Fatalf("expected aws hint, got %v", cloud)
	}
}
