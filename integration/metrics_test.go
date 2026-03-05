//go:build integration

package integration_test

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// percentile returns the p-th percentile (0.0–1.0) of a pre-sorted duration slice.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// writeMetricsJSON writes a map as indented JSON to $DNSTT_METRICS_DIR/<name>.
// Falls back to the current directory if the env var is not set.
// Logs the path on success; logs a warning on failure (does not fail the test).
func writeMetricsJSON(t testing.TB, name string, metrics map[string]any) {
	t.Helper()
	dir := os.Getenv("DNSTT_METRICS_DIR")
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("writeMetricsJSON: mkdir %s: %v", dir, err)
		return
	}
	path := filepath.Join(dir, name)
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		t.Logf("writeMetricsJSON: marshal: %v", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Logf("writeMetricsJSON: write %s: %v", path, err)
		return
	}
	t.Logf("metrics written to %s", path)
}

// collectRTTs sends n 1-byte echo pings over conn and returns the RTTs sorted
// in ascending order.  A 10ms pause between pings prevents ACK-triggered
// back-to-back polls from masking the poll-timer latency floor.
func collectRTTs(t testing.TB, conn net.Conn, n int) []time.Duration {
	t.Helper()
	rtts := make([]time.Duration, 0, n)
	ping := []byte{0x42}
	pong := make([]byte, 1)

	for i := 0; i < n; i++ {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		start := time.Now()
		if _, err := conn.Write(ping); err != nil {
			t.Fatalf("collectRTTs write %d: %v", i, err)
		}
		if _, err := io.ReadFull(conn, pong); err != nil {
			t.Fatalf("collectRTTs read %d: %v", i, err)
		}
		rtts = append(rtts, time.Since(start))
		time.Sleep(10 * time.Millisecond)
	}
	conn.SetDeadline(time.Time{})

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts
}
