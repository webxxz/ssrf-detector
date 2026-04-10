package chain

import (
	"fmt"
	"testing"
	"time"
)

func TestMapInternalNetwork(t *testing.T) {
	m := MapInternalNetwork(func(target string, port int) (time.Duration, error) {
		if target == "127.0.0.1" && port == 2375 {
			return 10 * time.Millisecond, nil
		}
		return 25 * time.Millisecond, fmt.Errorf("closed")
	})
	if len(m.CriticalServices) == 0 {
		t.Fatal("expected critical services")
	}
}
