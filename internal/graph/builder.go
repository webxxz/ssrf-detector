package graph

import (
	"fmt"
	"strconv"
	"strings"

	"ssrf-detector/internal/scoring"
)

// BuildGraph builds an SSRF intelligence graph from scored findings.
func BuildGraph(findings []*scoring.ScoredFinding) *SSRFGraph {
	g := &SSRFGraph{
		Nodes: map[string]*GraphNode{},
		Edges: make([]*GraphEdge, 0),
	}

	for _, sf := range findings {
		if sf == nil || sf.Finding == nil {
			continue
		}
		f := sf.Finding
		endpoint := ""
		if f.Target != nil && f.Target.URL != nil {
			endpoint = f.Target.URL.String()
		}
		if endpoint == "" {
			continue
		}

		conf := float64(f.ConfidenceScore) / 100.0
		if conf < 0 {
			conf = 0
		}

		endpointID := "endpoint:" + endpoint
		upsertNode(g, endpointID, "endpoint", endpoint, conf)

		if strings.TrimSpace(f.VulnerableParameter) != "" {
			paramID := "parameter:" + f.VulnerableParameter
			upsertNode(g, paramID, "parameter", f.VulnerableParameter, conf)
			addEdge(g, endpointID, paramID, "has_param", "vulnerable parameter identified")

			for _, ip := range f.InternalIPsReached {
				if strings.TrimSpace(ip) == "" {
					continue
				}
				ipID := "ip:" + ip
				upsertNode(g, ipID, "ip", ip, conf)
				addEdge(g, paramID, ipID, "reaches", "internal SSRF reachability evidence")

				for _, port := range inferPortsFromFinding(sf) {
					portVal := strconv.Itoa(port)
					portID := fmt.Sprintf("port:%s:%s", ip, portVal)
					upsertNode(g, portID, "port", portVal, conf)
					addEdge(g, ipID, portID, "has_open_port", "inferred from chain/evidence")

					service := inferServiceFromPort(port)
					if service == "" {
						continue
					}
					serviceID := "service:" + service
					upsertNode(g, serviceID, "service", service, conf)
					addEdge(g, portID, serviceID, "runs", "service fingerprint inference")

					for _, chainNode := range inferChainNodes(sf) {
						chainID := "chain:" + chainNode
						upsertNode(g, chainID, "chain", chainNode, conf)
						addEdge(g, serviceID, chainID, "chains_to", "attack-chain reasoning")
					}
				}
			}
		}
	}

	return g
}

func upsertNode(g *SSRFGraph, id, t, value string, conf float64) {
	if existing, ok := g.Nodes[id]; ok {
		if conf > existing.Confidence {
			existing.Confidence = conf
		}
		return
	}
	g.Nodes[id] = &GraphNode{ID: id, Type: t, Value: value, Confidence: conf, Edges: make([]*GraphEdge, 0)}
}

func addEdge(g *SSRFGraph, from, to, relation, evidence string) {
	edge := &GraphEdge{From: from, To: to, Relation: relation, Evidence: evidence}
	g.Edges = append(g.Edges, edge)
	if n, ok := g.Nodes[from]; ok {
		n.Edges = append(n.Edges, edge)
	}
}

func inferPortsFromFinding(sf *scoring.ScoredFinding) []int {
	out := make([]int, 0)
	seen := map[int]struct{}{}
	if sf == nil || sf.Finding == nil {
		return out
	}
	for _, chain := range sf.Finding.AttackChains {
		t := strings.ToLower(chain.Title)
		if strings.Contains(t, "redis") {
			seen[6379] = struct{}{}
		}
		if strings.Contains(t, "kube") {
			seen[10250] = struct{}{}
		}
		if strings.Contains(t, "elastic") {
			seen[9200] = struct{}{}
		}
		if strings.Contains(t, "jenkins") {
			seen[8080] = struct{}{}
		}
	}
	if sf.ReachesRedisPort {
		seen[6379] = struct{}{}
	}
	for p := range seen {
		out = append(out, p)
	}
	return out
}

func inferServiceFromPort(port int) string {
	switch port {
	case 6379:
		return "redis"
	case 10250, 6443:
		return "kubernetes"
	case 9200:
		return "elasticsearch"
	case 8080:
		return "jenkins"
	default:
		return ""
	}
}

func inferChainNodes(sf *scoring.ScoredFinding) []string {
	results := make([]string, 0)
	seen := map[string]struct{}{}
	if sf == nil || sf.Finding == nil {
		return results
	}
	for _, c := range sf.Finding.AttackChains {
		t := strings.ToLower(c.Title + " " + c.Impact)
		if strings.Contains(t, "rce") || strings.Contains(t, "command execution") {
			seen["RCE"] = struct{}{}
		}
		if strings.Contains(t, "credential") || strings.Contains(t, "iam") {
			seen["CredTheft"] = struct{}{}
		}
	}
	if sf.RCEChain {
		seen["RCE"] = struct{}{}
	}
	if sf.CredentialTheftChain {
		seen["CredTheft"] = struct{}{}
	}
	for k := range seen {
		results = append(results, k)
	}
	return results
}
