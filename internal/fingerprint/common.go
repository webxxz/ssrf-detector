package fingerprint

import "time"

// ProbeExecutor executes a service-specific probe.
type ProbeExecutor func(target string, port int, path string, payload string) (statusCode int, body []byte, latency time.Duration, err error)

// ServiceFingerprintResult normalizes service-specific probe results.
type ServiceFingerprintResult struct {
	Service       string
	Reachable     bool
	Authenticated bool
	Version       string
	Details       map[string]string
	Confirmed     bool
}

// FingerprintOpenPort runs service fingerprinting for known SSRF-relevant ports.
func FingerprintOpenPort(target string, port int, probe ProbeExecutor) ServiceFingerprintResult {
	switch port {
	case 6379:
		r := ProbeRedis(target, probe)
		return ServiceFingerprintResult{
			Service:       "redis",
			Reachable:     r.Reachable,
			Authenticated: r.Authenticated,
			Version:       r.Version,
			Details:       map[string]string{"service": "redis"},
			Confirmed:     r.Reachable,
		}
	case 10250, 6443:
		r := ProbeKubernetes(probe)
		return ServiceFingerprintResult{
			Service:       "kubernetes",
			Reachable:     r.Reachable,
			Authenticated: r.Authenticated,
			Version:       r.APIVersion,
			Details:       map[string]string{"api_version": r.APIVersion},
			Confirmed:     r.Reachable,
		}
	case 9200:
		r := ProbeElasticsearch(target, probe)
		return ServiceFingerprintResult{
			Service:       "elasticsearch",
			Reachable:     r.Reachable,
			Authenticated: false,
			Version:       "",
			Details: map[string]string{
				"cluster_name": r.ClusterName,
				"node_count":   itoa(r.NodeCount),
			},
			Confirmed: r.Reachable,
		}
	case 8080:
		r := ProbeJenkins(target, probe)
		return ServiceFingerprintResult{
			Service:       "jenkins",
			Reachable:     r.Reachable,
			Authenticated: r.Authenticated,
			Version:       "",
			Details:       map[string]string{"job_count": itoa(r.JobCount)},
			Confirmed:     r.Reachable,
		}
	default:
		return ServiceFingerprintResult{}
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	digits := make([]byte, 0, 10)
	for v > 0 {
		digits = append([]byte{byte('0' + (v % 10))}, digits...)
		v /= 10
	}
	return sign + string(digits)
}
