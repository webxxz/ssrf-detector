package chain

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestMapInternalNetworkWithFingerprintUpgradesServiceExposure(t *testing.T) {
	m := MapInternalNetworkWithFingerprint(
		func(target string, port int) (time.Duration, error) {
			if target == "127.0.0.1" && port == 6379 {
				return 10 * time.Millisecond, nil
			}
			return 20 * time.Millisecond, fmt.Errorf("closed")
		},
		func(target string, port int, path string, payload string) (int, []byte, time.Duration, error) {
			if target == "127.0.0.1" && port == 6379 {
				return 200, []byte("-ERR unknown command, redis server"), 5 * time.Millisecond, nil
			}
			return 0, nil, 0, fmt.Errorf("unreachable")
		},
	)

	var redisExposure *PortExposure
	for i := range m.Exposures {
		ex := &m.Exposures[i]
		if ex.Target == "127.0.0.1" && ex.Port == 6379 {
			redisExposure = ex
			break
		}
	}

	if redisExposure == nil {
		t.Fatal("expected redis exposure")
	}
	if redisExposure.State != "open" {
		t.Fatalf("expected open state, got %s", redisExposure.State)
	}
	if !strings.EqualFold(redisExposure.Service, "redis") {
		t.Fatalf("expected redis service, got %s", redisExposure.Service)
	}
	if !redisExposure.Critical || !redisExposure.UpgradeCandidate {
		t.Fatalf("expected critical + upgrade candidate after fingerprint, got critical=%v upgrade=%v", redisExposure.Critical, redisExposure.UpgradeCandidate)
	}
}
