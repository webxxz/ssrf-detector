package fingerprint

import "strings"

// RedisResult contains Redis probe output.
type RedisResult struct {
	Reachable     bool
	Authenticated bool
	Version       string
}

// ProbeRedis fingerprints Redis using inline error and optional gopher PING.
func ProbeRedis(target string, probe ProbeExecutor) RedisResult {
	if probe == nil {
		return RedisResult{Reachable: true, Authenticated: false, Version: "unknown"}
	}
	_, body, _, err := probe(target, 6379, "", "")
	if err == nil && looksLikeRedis(body) {
		return RedisResult{Reachable: true, Authenticated: true, Version: inferRedisVersion(body)}
	}

	_, gopherBody, _, gopherErr := probe(target, 6379, "", "gopher://"+target+":6379/_PING%0D%0A")
	if gopherErr == nil && (strings.Contains(strings.ToUpper(string(gopherBody)), "PONG") || looksLikeRedis(gopherBody)) {
		return RedisResult{Reachable: true, Authenticated: true, Version: inferRedisVersion(gopherBody)}
	}

	if err == nil || gopherErr == nil {
		return RedisResult{Reachable: true, Authenticated: false, Version: "unknown"}
	}
	return RedisResult{Reachable: false}
}

func looksLikeRedis(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "redis") || strings.Contains(s, "-err") || strings.Contains(s, "wrongtype")
}

func inferRedisVersion(body []byte) string {
	s := strings.ToLower(string(body))
	idx := strings.Index(s, "redis_version:")
	if idx == -1 {
		return "unknown"
	}
	rem := s[idx+len("redis_version:"):]
	for i, r := range rem {
		if r == '\n' || r == '\r' || r == ' ' {
			return strings.TrimSpace(rem[:i])
		}
	}
	return strings.TrimSpace(rem)
}
