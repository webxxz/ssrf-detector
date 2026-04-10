package surface

import "testing"

func TestExtractJSONBodyPoints(t *testing.T) {
	body := []byte(`{"url":"http://example.com","meta":{"callback":"/internal/path"}}`)
	points := ExtractJSONBodyPoints(body)
	if len(points) < 2 {
		t.Fatalf("expected at least 2 points, got %d", len(points))
	}
}
