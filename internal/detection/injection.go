package detection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"ssrf-detector/internal/core"
)

func cloneTarget(target *core.Target) *core.Target {
	if target == nil {
		return nil
	}

	cloned := *target
	if target.URL != nil {
		u := *target.URL
		cloned.URL = &u
	}
	if target.Headers != nil {
		cloned.Headers = target.Headers.Clone()
	}
	if target.Body != nil {
		cloned.Body = append([]byte(nil), target.Body...)
	}
	return &cloned
}

func applyInjectionPayload(target *core.Target, payload string) (*core.Target, error) {
	cloned := cloneTarget(target)
	if cloned == nil {
		return nil, fmt.Errorf("target is nil")
	}
	if cloned.URL == nil {
		return nil, fmt.Errorf("target URL is nil")
	}

	switch cloned.InjectionPoint.Type {
	case core.InjectionQuery:
		q := cloned.URL.Query()
		q.Set(cloned.InjectionPoint.Name, payload)
		cloned.URL.RawQuery = q.Encode()
	case core.InjectionHeader:
		if cloned.Headers == nil {
			cloned.Headers = make(http.Header)
		}
		cloned.Headers.Set(cloned.InjectionPoint.Name, payload)
	case core.InjectionPath:
		if err := injectPathSegment(cloned, payload); err != nil {
			return nil, err
		}
	case core.InjectionBody, core.InjectionMultipart:
		if err := injectBodyParam(cloned, payload); err != nil {
			return nil, err
		}
	case core.InjectionJSON:
		if err := injectJSONField(cloned, payload); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported injection type: %s", cloned.InjectionPoint.Type)
	}

	return cloned, nil
}

func buildRequestFromTarget(target *core.Target) (*http.Request, error) {
	var bodyReader *bytes.Reader
	if len(target.Body) > 0 {
		bodyReader = bytes.NewReader(target.Body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(target.Method, target.URL.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range target.Headers {
		req.Header[k] = v
	}

	return req, nil
}

func injectPathSegment(target *core.Target, payload string) error {
	path := strings.TrimPrefix(target.URL.Path, "/")
	if path == "" {
		return fmt.Errorf("path injection requested but URL has no path segments")
	}

	segments := strings.Split(path, "/")
	pos := target.InjectionPoint.Position
	if pos < 0 || pos >= len(segments) {
		for i, segment := range segments {
			if segment == target.InjectionPoint.Name {
				pos = i
				break
			}
		}
	}
	if pos < 0 || pos >= len(segments) {
		return fmt.Errorf("invalid path segment index for injection")
	}

	segments[pos] = url.PathEscape(payload)
	target.URL.Path = "/" + strings.Join(segments, "/")
	return nil
}

func injectBodyParam(target *core.Target, payload string) error {
	form, err := url.ParseQuery(string(target.Body))
	if err != nil {
		return fmt.Errorf("failed to parse form body: %w", err)
	}
	form.Set(target.InjectionPoint.Name, payload)
	target.Body = []byte(form.Encode())

	if target.Headers == nil {
		target.Headers = make(http.Header)
	}
	if target.Headers.Get("Content-Type") == "" {
		target.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return nil
}

func injectJSONField(target *core.Target, payload string) error {
	var obj map[string]interface{}
	if err := json.Unmarshal(target.Body, &obj); err != nil {
		return fmt.Errorf("failed to parse json body: %w", err)
	}

	obj[target.InjectionPoint.Name] = payload
	updated, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to encode json body: %w", err)
	}
	target.Body = updated

	if target.Headers == nil {
		target.Headers = make(http.Header)
	}
	if target.Headers.Get("Content-Type") == "" {
		target.Headers.Set("Content-Type", "application/json")
	}
	return nil
}
