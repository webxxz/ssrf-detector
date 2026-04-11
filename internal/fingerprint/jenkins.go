package fingerprint

import "strings"

// JenkinsResult contains Jenkins probe output.
type JenkinsResult struct {
	Reachable     bool
	Authenticated bool
	JobCount      int
}

// ProbeJenkins probes /api/json for Jenkins signature.
func ProbeJenkins(target string, probe ProbeExecutor) JenkinsResult {
	if probe == nil {
		return JenkinsResult{Reachable: true}
	}

	status, body, _, err := probe(target, 8080, "/api/json", "")
	if err != nil {
		return JenkinsResult{Reachable: false}
	}
	text := strings.ToLower(string(body))
	if !strings.Contains(text, "\"jobs\"") {
		return JenkinsResult{Reachable: false}
	}

	return JenkinsResult{
		Reachable:     true,
		Authenticated: status < 401,
		JobCount:      countJSONArrayItems(text, "jobs"),
	}
}
