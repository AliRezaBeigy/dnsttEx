//go:build integration

package integration_test

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestConcurrent opens 10 simultaneous TCP connections through the tunnel
// and verifies each can transfer data independently.  This exercises smux
// stream multiplexing over a single KCP session.  Each goroutine fills its
// payload with its own ID byte to detect cross-stream data corruption.
func TestConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent test in short mode")
	}

	h := newTunnelHarness(t, globalServerBin, globalClientBin)

	const (
		numConns       = 10
		payloadPerConn = 8 * 1024 // 8 KB per connection per direction
	)

	var wg sync.WaitGroup
	errc := make(chan error, numConns)

	start := time.Now()
	for id := 0; id < numConns; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", h.ClientAddr, 15*time.Second)
			if err != nil {
				errc <- fmt.Errorf("conn %d dial: %v", id, err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(120 * time.Second))

			// Fill payload with the connection ID so we can detect mixing.
			payload := make([]byte, payloadPerConn)
			for j := range payload {
				payload[j] = byte(id)
			}
			recvBuf := make([]byte, payloadPerConn)

			if _, err := conn.Write(payload); err != nil {
				errc <- fmt.Errorf("conn %d write: %v", id, err)
				return
			}
			if _, err := io.ReadFull(conn, recvBuf); err != nil {
				errc <- fmt.Errorf("conn %d read: %v", id, err)
				return
			}

			// Verify data integrity — no byte should have been altered or mixed.
			for j, b := range recvBuf {
				if b != byte(id) {
					errc <- fmt.Errorf("conn %d: byte[%d]=%d, expected %d (data corruption)", id, j, b, id)
					return
				}
			}
		}(id)
	}

	wg.Wait()
	close(errc)

	duration := time.Since(start)
	totalBytes := int64(numConns * payloadPerConn * 2) // both directions
	throughput := float64(totalBytes) / duration.Seconds()

	for err := range errc {
		t.Error(err)
	}

	t.Logf("%d concurrent streams: %d total bytes in %v (%.1f bytes/s)",
		numConns, totalBytes, duration.Round(time.Millisecond), throughput)

	writeMetricsJSON(t, "concurrent.json", map[string]any{
		"num_connections":      numConns,
		"payload_per_conn":     payloadPerConn,
		"total_bytes":          totalBytes,
		"duration_ms":          duration.Milliseconds(),
		"aggregate_bytes_per_s": throughput,
	})
}

// BenchmarkConcurrent benchmarks aggregate throughput with multiple simultaneous
// smux streams.  Each iteration opens b.N goroutines, sends 4 KB each, and
// reads the echo back.  Run with small -benchtime=Nx (e.g., -benchtime=5x).
func BenchmarkConcurrent(b *testing.B) {
	h := newTunnelHarness(b, globalServerBin, globalClientBin)

	const payloadPerConn = 4 * 1024 // 4 KB
	b.SetBytes(int64(b.N) * payloadPerConn * 2)
	b.ResetTimer()

	var wg sync.WaitGroup
	for id := 0; id < b.N; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", h.ClientAddr, 15*time.Second)
			if err != nil {
				b.Errorf("conn %d: %v", id, err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(120 * time.Second))

			payload := make([]byte, payloadPerConn)
			recvBuf := make([]byte, payloadPerConn)
			conn.Write(payload)
			io.ReadFull(conn, recvBuf)
		}(id)
	}
	wg.Wait()
}
