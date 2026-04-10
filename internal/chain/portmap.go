package chain

import "time"

const portFilteredStateLatencyThreshold = 1500 * time.Millisecond

var InternalTargets = []string{
	"127.0.0.1", "10.0.0.1", "192.168.1.1",
	"172.16.0.1", "169.254.169.254",
}

var SensitivePorts = []int{
	22, 3306, 5432, 6379, 9200, 8500, 2375, 10250, 8080,
}

// ProbeFunc executes a single SSRF timing/availability probe.
type ProbeFunc func(target string, port int) (time.Duration, error)

type PortExposure struct {
	Target           string        `json:"target"`
	Port             int           `json:"port"`
	Service          string        `json:"service"`
	State            string        `json:"state"`
	Latency          time.Duration `json:"latency"`
	Critical         bool          `json:"critical"`
	UpgradeCandidate bool          `json:"upgrade_candidate"`
}

type NetworkMap struct {
	GeneratedAt      time.Time        `json:"generated_at"`
	Reachability     map[string][]int `json:"reachability"`
	Exposures        []PortExposure   `json:"exposures"`
	CriticalServices []PortExposure   `json:"critical_services"`
}

// MapInternalNetwork builds an internal reachability map from an SSRF probe oracle.
func MapInternalNetwork(ssrfFunc ProbeFunc) *NetworkMap {
	m := &NetworkMap{
		GeneratedAt:  time.Now(),
		Reachability: map[string][]int{},
		Exposures:    make([]PortExposure, 0),
	}
	if ssrfFunc == nil {
		return m
	}

	for _, target := range InternalTargets {
		for _, port := range SensitivePorts {
			latency, err := ssrfFunc(target, port)
			state := "closed"
			if err == nil {
				state = "open"
			} else if latency > portFilteredStateLatencyThreshold {
				state = "filtered"
			}
			ex := PortExposure{
				Target:           target,
				Port:             port,
				Service:          serviceNameForPort(port),
				State:            state,
				Latency:          latency,
				Critical:         isCriticalPort(port),
				UpgradeCandidate: isUpgradeCandidatePort(port),
			}
			m.Exposures = append(m.Exposures, ex)
			if state == "open" {
				m.Reachability[target] = append(m.Reachability[target], port)
				if ex.Critical || ex.UpgradeCandidate {
					m.CriticalServices = append(m.CriticalServices, ex)
				}
			}
		}
	}
	return m
}

func isCriticalPort(port int) bool {
	return port == 2375 || port == 10250 || port == 6379
}

func isUpgradeCandidatePort(port int) bool {
	return port == 2375 || port == 10250
}

func serviceNameForPort(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 9200:
		return "elasticsearch"
	case 8500:
		return "consul"
	case 2375:
		return "docker"
	case 10250:
		return "kubelet"
	case 8080:
		return "admin"
	default:
		return "unknown"
	}
}
