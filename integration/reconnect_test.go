//go:build integration

package integration_test

import (
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// BenchmarkReconnect measures the time from server disruption to the first
// successful echo on a new session through the same client.
//
// The dnstt-client already implements automatic session recreation
// (sessionManager.createSession) which detects the dead KCP session via the
// smux keepalive timeout (KeepAliveTimeout=30s) and reconnects automatically.
// This benchmark measures the end-to-end recovery latency.
func BenchmarkReconnect(b *testing.B) {
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		func() {
			// Fresh harness per iteration so each reconnect starts clean.
			h := newTunnelHarness(b, globalServerBin, globalClientBin)
			defer h.Teardown()

			// Verify the tunnel is working before disruption.
			conn := h.dialTunnel(b)
			pingPong(b, conn, "pre-disruption")
			conn.Close()

			// Kill the server to simulate an abrupt disruption.
			h.serverCmd.Process.Kill()
			h.serverCmd.Wait()

			// On some platforms (Windows), the OS holds the UDP port briefly
			// after process exit. Give it a moment before rebinding.
			time.Sleep(500 * time.Millisecond)

			// Restart the server on the same UDP port with the same key.
			newServerCmd := exec.Command(h.serverBin,
				"-udp", h.dnsUDPAddr,
				"-privkey", h.privkeyHex,
				h.domain,
				h.echoLn.Addr().String(),
			)
			newServerCmd.Stderr = os.Stderr
			if err := newServerCmd.Start(); err != nil {
				b.Fatalf("restart server: %v", err)
			}
			h.serverCmd = newServerCmd

			// Measure time until a successful echo completes.
			b.StartTimer()
			restartTime := time.Now()

			const maxWait = 60 * time.Second
			deadline := time.Now().Add(maxWait)
			reconnected := false

			for time.Now().Before(deadline) {
				c2, err := net.DialTimeout("tcp", h.ClientAddr, 2*time.Second)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				c2.SetDeadline(time.Now().Add(10 * time.Second))
				_, wErr := c2.Write([]byte{0x42})
				pong := make([]byte, 1)
				_, rErr := io.ReadFull(c2, pong)
				c2.Close()

				if wErr == nil && rErr == nil {
					reconnected = true
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			elapsed := time.Since(restartTime)
			b.StopTimer()

			if !reconnected {
				b.Fatalf("iteration %d: failed to reconnect within %v", i, maxWait)
			}
			b.ReportMetric(float64(elapsed.Milliseconds()), "ms/reconnect")
		}()
	}
}

// TestReconnect is a single-shot reconnect test that verifies the client
// automatically recovers after the server restarts.
func TestReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping reconnect test in short mode")
	}

	h := newTunnelHarness(t, globalServerBin, globalClientBin)

	// Verify working before disruption.
	conn := h.dialTunnel(t)
	pingPong(t, conn, "pre-disruption")
	conn.Close()

	// Kill and restart server.
	h.serverCmd.Process.Kill()
	h.serverCmd.Wait()
	time.Sleep(500 * time.Millisecond)

	newServerCmd := exec.Command(h.serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		h.domain,
		h.echoLn.Addr().String(),
	)
	newServerCmd.Stderr = os.Stderr
	if err := newServerCmd.Start(); err != nil {
		t.Fatalf("restart server: %v", err)
	}
	h.serverCmd = newServerCmd

	// Poll until a successful echo is achieved.
	restartTime := time.Now()
	deadline := time.Now().Add(60 * time.Second)
	reconnected := false

	for time.Now().Before(deadline) {
		c2, err := net.DialTimeout("tcp", h.ClientAddr, 2*time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c2.SetDeadline(time.Now().Add(10 * time.Second))
		_, wErr := c2.Write([]byte{0x42})
		pong := make([]byte, 1)
		_, rErr := io.ReadFull(c2, pong)
		c2.Close()

		if wErr == nil && rErr == nil {
			reconnected = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	elapsed := time.Since(restartTime)
	if !reconnected {
		t.Fatal("failed to reconnect within 60s after server restart")
	}
	t.Logf("Reconnected in %v", elapsed)
	writeMetricsJSON(t, "reconnect.json", map[string]any{
		"reconnect_ms": elapsed.Milliseconds(),
	})
}
