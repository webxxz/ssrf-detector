package fingerprint

import "strings"

// K8sResult contains Kubernetes probe output.
type K8sResult struct {
	Reachable     bool
	Authenticated bool
	APIVersion    string
}

// ProbeKubernetes probes kubelet, kube-apiserver, and service IP endpoints.
func ProbeKubernetes(probe ProbeExecutor) K8sResult {
	if probe == nil {
		return K8sResult{Reachable: true, Authenticated: false, APIVersion: "unknown"}
	}

	endpoints := []struct {
		target string
		port   int
		path   string
	}{
		{target: "10.0.0.1", port: 10250, path: "/pods"},
		{target: "10.0.0.1", port: 6443, path: "/api"},
		{target: "10.96.0.1", port: 443, path: "/"},
	}

	for _, ep := range endpoints {
		status, body, _, err := probe(ep.target, ep.port, ep.path, "")
		if err != nil {
			continue
		}
		text := strings.ToLower(string(body))
		if strings.Contains(text, "apiversion") {
			return K8sResult{Reachable: true, Authenticated: status < 401, APIVersion: extractJSONValue(text, "apiversion")}
		}
		if status == 401 || status == 403 {
			return K8sResult{Reachable: true, Authenticated: false, APIVersion: "unknown"}
		}
	}

	return K8sResult{Reachable: false}
}
