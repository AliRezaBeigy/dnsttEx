//go:build integration

package integration_test

import (
	"io"
	"testing"
	"time"
)

// BenchmarkThroughput measures bytes/second through the full DNS tunnel stack.
// A single persistent TCP connection sends 4 KB chunks and reads them back.
// b.SetBytes causes go test -bench to report MB/s automatically.
func BenchmarkThroughput(b *testing.B) {
	h := newTunnelHarness(b, globalServerBin, globalClientBin)
	conn := h.dialTunnel(b)
	defer conn.Close()

	const chunkSize = 4096
	payload := make([]byte, chunkSize)
	recvBuf := make([]byte, chunkSize)

	// Warm up: establish the KCP session and smux stream before timing.
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	conn.Write(payload)
	io.ReadFull(conn, recvBuf)

	b.SetBytes(int64(chunkSize)) // bytes per iteration (one direction; echo doubles it)
	b.ResetTimer()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(conn, recvBuf); err != nil {
			b.Fatalf("read: %v", err)
		}
	}

	elapsed := time.Since(start)
	// Both directions: sent + echoed.
	totalBytes := int64(b.N) * chunkSize * 2
	b.ReportMetric(float64(totalBytes)/elapsed.Seconds(), "bytes/sec")
}
