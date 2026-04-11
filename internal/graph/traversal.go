package graph

import "sort"

const cvssCredentialTheft = 9.8

// FindAttackPaths traverses from endpoint nodes and returns ranked high-impact paths.
func FindAttackPaths(graph *SSRFGraph) []AttackPath {
	if graph == nil || len(graph.Nodes) == 0 {
		return nil
	}

	paths := make([]AttackPath, 0)
	for _, n := range graph.Nodes {
		if n.Type != "endpoint" {
			continue
		}
		dfs(graph, n.ID, map[string]bool{}, []string{}, []string{}, &paths)
	}

	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].CVSS == paths[j].CVSS {
			return paths[i].Length > paths[j].Length
		}
		return paths[i].CVSS > paths[j].CVSS
	})
	return paths
}

func dfs(graph *SSRFGraph, current string, seen map[string]bool, nodeIDs, nodeTypes []string, out *[]AttackPath) {
	if seen[current] {
		return
	}
	seen[current] = true
	defer func() { seen[current] = false }()

	node, ok := graph.Nodes[current]
	if !ok {
		return
	}

	nodeIDs = append(nodeIDs, current)
	nodeTypes = append(nodeTypes, node.Type)

	if node.Type == "chain" && (node.Value == "RCE" || node.Value == "CredTheft") {
		cvss := 8.0
		if node.Value == "RCE" {
			cvss = 9.0
		}
		if node.Value == "CredTheft" {
			// Credential-theft is treated as critical here because it often implies account takeover.
			cvss = cvssCredentialTheft
		}
		*out = append(*out, AttackPath{
			NodeIDs:   append([]string(nil), nodeIDs...),
			NodeTypes: append([]string(nil), nodeTypes...),
			Impact:    node.Value,
			CVSS:      cvss,
			Length:    len(nodeIDs),
		})
		return
	}

	for _, e := range node.Edges {
		dfs(graph, e.To, seen, nodeIDs, nodeTypes, out)
	}
}
