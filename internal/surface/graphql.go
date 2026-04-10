package surface

import (
	"encoding/json"
	"fmt"
	"strings"

	"ssrf-detector/internal/core"
)

var graphqlSensitiveNames = map[string]struct{}{
	"url": {}, "uri": {}, "src": {}, "endpoint": {}, "webhook": {}, "callback": {},
}

// ExtractGraphQLSSRFPoints parses an introspection response and returns candidate injection points.
func ExtractGraphQLSSRFPoints(schema []byte) []core.InjectionPoint {
	var root interface{}
	if err := json.Unmarshal(schema, &root); err != nil {
		return nil
	}

	out := make([]core.InjectionPoint, 0)
	seen := map[string]struct{}{}
	var walk func(node interface{}, path []string)
	walk = func(node interface{}, path []string) {
		switch n := node.(type) {
		case map[string]interface{}:
			if nameRaw, ok := n["name"].(string); ok {
				name := strings.ToLower(nameRaw)
				if _, sensitive := graphqlSensitiveNames[name]; sensitive && looksLikeGraphQLStringType(n["type"]) {
					full := append(path, nameRaw)
					key := strings.Join(full, ".")
					if _, exists := seen[key]; !exists {
						seen[key] = struct{}{}
						out = append(out, core.InjectionPoint{
							Type:    core.InjectionJSON,
							Name:    key,
							Context: core.ContextJSON,
						})
					}
				}
			}
			for k, v := range n {
				walk(v, append(path, k))
			}
		case []interface{}:
			for i, v := range n {
				walk(v, append(path, fmt.Sprintf("[%d]", i)))
			}
		}
	}

	walk(root, nil)
	return out
}

func looksLikeGraphQLStringType(v interface{}) bool {
	m, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	if name, ok := m["name"].(string); ok && strings.EqualFold(name, "String") {
		return true
	}
	if kind, ok := m["kind"].(string); ok && strings.EqualFold(kind, "SCALAR") {
		if name, ok := m["name"].(string); ok && strings.EqualFold(name, "String") {
			return true
		}
	}
	return looksLikeGraphQLStringType(m["ofType"])
}
