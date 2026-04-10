package surface

import (
	"testing"

	"ssrf-detector/internal/core"
)

func TestExtractJSONBodyPoints(t *testing.T) {
	body := []byte(`{"url":"http://example.com","meta":{"callback":"/internal/path"}}`)
	points := ExtractJSONBodyPoints(body)
	if len(points) < 2 {
		t.Fatalf("expected at least 2 points, got %d", len(points))
	}
	seen := map[string]core.InjectionPoint{}
	for _, p := range points {
		seen[p.Name] = p
	}
	url, ok := seen["url"]
	if !ok || url.Type != core.InjectionJSON || url.Context != core.ContextJSON {
		t.Fatalf("expected url injection point with json context, got %+v", url)
	}
	callback, ok := seen["meta.callback"]
	if !ok || callback.Type != core.InjectionJSON || callback.Context != core.ContextJSON {
		t.Fatalf("expected callback injection point with json context, got %+v", callback)
	}
}
