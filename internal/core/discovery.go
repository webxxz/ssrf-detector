package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DiscoverInjectionPoints finds likely URL injection points from target metadata.
func DiscoverInjectionPoints(target *Target) []InjectionPoint {
	if target == nil {
		return nil
	}

	points := make([]InjectionPoint, 0)
	seen := make(map[string]bool)

	addPoint := func(p InjectionPoint) {
		key := fmt.Sprintf("%s|%s|%d|%s", p.Type, p.Name, p.Position, p.Context)
		if seen[key] {
			return
		}
		seen[key] = true
		points = append(points, p)
	}

	if target.URL != nil {
		for name := range target.URL.Query() {
			addPoint(InjectionPoint{Type: InjectionQuery, Name: name, Context: ContextURLEncoded})
		}

		path := strings.Trim(target.URL.Path, "/")
		if path != "" {
			segments := strings.Split(path, "/")
			for i, segment := range segments {
				if segment == "" {
					continue
				}
				addPoint(InjectionPoint{
					Type:     InjectionPath,
					Name:     segment,
					Position: i,
					Context:  ContextRaw,
				})
			}
		}
	}

	discoverHeaderPoints(target.Headers, addPoint)
	discoverBodyPoints(target, addPoint)

	return points
}

func discoverHeaderPoints(headers http.Header, addPoint func(InjectionPoint)) {
	if headers == nil {
		return
	}

	interesting := map[string]bool{
		"x-forwarded-host":   true,
		"x-forwarded-server": true,
		"x-original-url":     true,
		"x-rewrite-url":      true,
		"referer":            true,
		"origin":             true,
	}

	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		lower := strings.ToLower(key)
		value := values[0]
		if interesting[lower] || looksLikeURL(value) {
			addPoint(InjectionPoint{
				Type:    InjectionHeader,
				Name:    key,
				Context: ContextRaw,
			})
		}
	}
}

func discoverBodyPoints(target *Target, addPoint func(InjectionPoint)) {
	if len(target.Body) == 0 {
		return
	}

	contentType := strings.ToLower(strings.TrimSpace(target.Headers.Get("Content-Type")))
	bodyStr := string(target.Body)

	if strings.Contains(contentType, "application/json") || strings.HasPrefix(strings.TrimSpace(bodyStr), "{") {
		var obj map[string]interface{}
		if err := json.Unmarshal(target.Body, &obj); err == nil {
			for key, value := range obj {
				if v, ok := value.(string); ok && looksLikeURL(v) {
					addPoint(InjectionPoint{Type: InjectionJSON, Name: key, Context: ContextJSON})
				}
			}
		}
	}

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if form, err := url.ParseQuery(bodyStr); err == nil {
			for key, values := range form {
				if len(values) > 0 {
					addPoint(InjectionPoint{Type: InjectionBody, Name: key, Context: ContextURLEncoded})
				}
			}
		}
	}
}

func looksLikeURL(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.HasPrefix(value, "//") {
		return len(value) > 2
	}
	return strings.HasPrefix(value, "http://") ||
		strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "ftp://")
}
