package graph

// GraphNode models one entity in SSRF attack surface intelligence.
type GraphNode struct {
	ID         string
	Type       string // endpoint | parameter | ip | port | service | chain
	Value      string
	Confidence float64
	Edges      []*GraphEdge
}

// GraphEdge links nodes with evidence-backed relations.
type GraphEdge struct {
	From     string
	To       string
	Relation string // has_param | reaches | has_open_port | runs | reveals | chains_to
	Evidence string
}

// SSRFGraph stores all SSRF reconnaissance and chain data.
type SSRFGraph struct {
	Nodes map[string]*GraphNode
	Edges []*GraphEdge
}

// AttackPath is one ranked endpoint-to-impact chain.
type AttackPath struct {
	NodeIDs   []string
	NodeTypes []string
	Impact    string
	CVSS      float64
	Length    int
}
