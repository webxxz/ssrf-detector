package surface

import (
	"encoding/json"
	"fmt"
	"strings"

	"ssrf-detector/internal/core"
)

var jsonSensitiveKeys = map[string]struct{}{
	"url": {}, "uri": {}, "src": {}, "endpoint": {}, "webhook": {}, "callback": {}, "redirect": {}, "dest": {}, "path": {},
}

// ExtractJSONBodyPoints recursively discovers URL-like injection candidates in JSON bodies.
func ExtractJSONBodyPoints(body []byte) []core.InjectionPoint {
	var root interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}

	out := make([]core.InjectionPoint, 0)
	seen := map[string]struct{}{}
	var walk func(node interface{}, path []string, key string)
	walk = func(node interface{}, path []string, key string) {
		switch n := node.(type) {
		case map[string]interface{}:
			for k, v := range n {
				walk(v, append(path, k), k)
			}
		case []interface{}:
			for i, v := range n {
				walk(v, append(path, fmt.Sprintf("[%d]", i)), key)
			}
		case string:
			if isSemanticallySensitive(key) || looksLikeURLOrPath(n) {
				pointName := strings.Join(path, ".")
				if _, ok := seen[pointName]; !ok {
					seen[pointName] = struct{}{}
					out = append(out, core.InjectionPoint{
						Type:    core.InjectionJSON,
						Name:    pointName,
						Context: core.ContextJSON,
					})
				}
			}
		}
	}

	walk(root, nil, "")
	return out
}

func isSemanticallySensitive(key string) bool {
	_, ok := jsonSensitiveKeys[strings.ToLower(key)]
	return ok
}

func looksLikeURLOrPath(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(l, "http://") ||
		strings.HasPrefix(l, "https://") ||
		strings.HasPrefix(l, "/") ||
		strings.HasPrefix(l, "../") ||
		strings.Contains(l, "://")
}
