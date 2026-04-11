package fingerprint

import "strings"

// ESResult contains Elasticsearch probe output.
type ESResult struct {
	Reachable   bool
	ClusterName string
	NodeCount   int
}

// ProbeElasticsearch probes /_cluster/health for Elasticsearch fingerprints.
func ProbeElasticsearch(target string, probe ProbeExecutor) ESResult {
	if probe == nil {
		return ESResult{Reachable: true}
	}

	_, body, _, err := probe(target, 9200, "/_cluster/health", "")
	if err != nil {
		return ESResult{Reachable: false}
	}
	text := strings.ToLower(string(body))
	if !strings.Contains(text, "cluster_name") {
		return ESResult{Reachable: false}
	}

	return ESResult{
		Reachable:   true,
		ClusterName: extractJSONValue(text, "cluster_name"),
		NodeCount:   extractJSONInt(text, "number_of_nodes"),
	}
}
