//go:build integration

package integration_test

import (
	"io"
	"testing"
	"time"
)

// BenchmarkLatency measures single-echo RTT through the full DNS tunnel stack.
// Each iteration sends 1 byte and reads 1 byte back.  The tunnel uses DNS
// polling (initPollDelay=500ms, maxPollDelay=2s), so RTTs are in the
// hundreds-of-milliseconds range.
func BenchmarkLatency(b *testing.B) {
	h := newTunnelHarness(b, globalServerBin, globalClientBin, nil)
	conn := h.dialTunnel(b)
	defer conn.Close()

	ping := []byte{0x42}
	pong := make([]byte, 1)

	// Warm up: one successful echo before timing starts.
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(ping); err != nil {
		b.Fatal(err)
	}
	if _, err := io.ReadFull(conn, pong); err != nil {
		b.Fatal(err)
	}
	if pong[0] != 0x42 {
		b.Fatal("warm-up echo byte mismatch")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		conn.Write(ping)
		if _, err := io.ReadFull(conn, pong); err != nil {
			b.Fatalf("read: %v", err)
		}
		if pong[0] != 0x42 {
			b.Fatalf("echoed byte %x, want 0x42", pong[0])
		}
		rtt := time.Since(start)
		b.ReportMetric(float64(rtt.Milliseconds()), "ms/rtt")
	}
}

// TestLatencyPercentiles collects 100 RTT samples and reports P50, P95, P99.
// Results are written to latency_percentiles.json in $DNSTT_METRICS_DIR.
func TestLatencyPercentiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping percentile test in short mode")
	}

	h := newTunnelHarness(t, globalServerBin, globalClientBin, nil)
	conn := h.dialTunnel(t)
	defer conn.Close()

	const n = 100
	rtts := collectRTTs(t, conn, n)

	p50 := percentile(rtts, 0.50)
	p95 := percentile(rtts, 0.95)
	p99 := percentile(rtts, 0.99)

	t.Logf("RTT over %d samples: P50=%v  P95=%v  P99=%v", n, p50, p95, p99)

	writeMetricsJSON(t, "latency_percentiles.json", map[string]any{
		"samples": n,
		"p50_ms":  p50.Milliseconds(),
		"p95_ms":  p95.Milliseconds(),
		"p99_ms":  p99.Milliseconds(),
		"min_ms":  rtts[0].Milliseconds(),
		"max_ms":  rtts[len(rtts)-1].Milliseconds(),
	})
}
