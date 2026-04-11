package fingerprint

import "strings"

func extractJSONValue(text, key string) string {
	needle := "\"" + strings.ToLower(key) + "\""
	idx := strings.Index(text, needle)
	if idx < 0 {
		return ""
	}
	rem := text[idx+len(needle):]
	colon := strings.Index(rem, ":")
	if colon < 0 {
		return ""
	}
	rem = strings.TrimSpace(rem[colon+1:])
	if len(rem) == 0 {
		return ""
	}
	if rem[0] == '"' {
		rem = rem[1:]
		end := strings.Index(rem, "\"")
		if end > 0 {
			return rem[:end]
		}
		return ""
	}
	for i, ch := range rem {
		if ch == ',' || ch == '}' || ch == '\n' || ch == '\r' {
			return strings.TrimSpace(rem[:i])
		}
	}
	return strings.TrimSpace(rem)
}

func extractJSONInt(text, key string) int {
	v := extractJSONValue(text, key)
	if v == "" {
		return 0
	}
	n := 0
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

func countJSONArrayItems(text, key string) int {
	needle := "\"" + strings.ToLower(key) + "\""
	idx := strings.Index(text, needle)
	if idx < 0 {
		return 0
	}
	rem := text[idx+len(needle):]
	open := strings.Index(rem, "[")
	if open < 0 {
		return 0
	}
	rem = rem[open+1:]
	close := strings.Index(rem, "]")
	if close < 0 {
		return 0
	}
	arr := strings.TrimSpace(rem[:close])
	if arr == "" {
		return 0
	}
	count := 1
	for _, ch := range arr {
		if ch == ',' {
			count++
		}
	}
	return count
}
