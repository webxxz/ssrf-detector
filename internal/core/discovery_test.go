package core

import (
	"net/http"
	"net/url"
	"testing"
)

func TestDiscoverInjectionPoints(t *testing.T) {
	parsed, err := url.Parse("https://example.com/api/v1/fetch?url=http://a&next=/home")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	target := &Target{
		URL:    parsed,
		Method: "POST",
		Headers: http.Header{
			"X-Forwarded-Host": []string{"https://a.example"},
			"Content-Type":     []string{"application/json"},
		},
		Body: []byte(`{"callback":"https://b.example/cb","name":"demo"}`),
	}

	points := DiscoverInjectionPoints(target)
	if len(points) == 0 {
		t.Fatal("expected discovered points")
	}

	hasType := func(injectionType InjectionType) bool {
		for _, p := range points {
			if p.Type == injectionType {
				return true
			}
		}
		return false
	}

	if !hasType(InjectionQuery) {
		t.Error("expected query injection point")
	}
	if !hasType(InjectionPath) {
		t.Error("expected path injection point")
	}
	if !hasType(InjectionHeader) {
		t.Error("expected header injection point")
	}
	if !hasType(InjectionJSON) {
		t.Error("expected json injection point")
	}
}

func TestDiscoverInjectionPointsSemanticNames(t *testing.T) {
	parsed, err := url.Parse("https://example.com/api/proxy?dest=internal-service&name=demo")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	target := &Target{
		URL:    parsed,
		Method: "POST",
		Headers: http.Header{
			"Content-Type": []string{"application/x-www-form-urlencoded"},
		},
		Body: []byte("callback=next-hop&name=demo"),
	}

	points := DiscoverInjectionPoints(target)
	if len(points) == 0 {
		t.Fatal("expected discovered points")
	}

	hasPoint := func(injectionType InjectionType, name string) bool {
		for _, p := range points {
			if p.Type == injectionType && p.Name == name {
				return true
			}
		}
		return false
	}

	if !hasPoint(InjectionQuery, "dest") {
		t.Error("expected semantic query parameter to be discovered")
	}
	if !hasPoint(InjectionBody, "callback") {
		t.Error("expected semantic body parameter to be discovered")
	}
}
