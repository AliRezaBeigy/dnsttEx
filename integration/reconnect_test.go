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
// The client detects a dead session when smux's KeepAliveTimeout fires (no
// PONG to PING) or when a stream operation fails. Tests use fast 1s/3s
// keepalive so recovery takes a few seconds.
func BenchmarkReconnect(b *testing.B) {
	b.StopTimer()

	reconnectEnv := map[string]string{
		"DNSTT_SMUX_KEEPALIVE_INTERVAL": "1s",
		"DNSTT_SMUX_KEEPALIVE_TIMEOUT":  "3s",
	}
	for i := 0; i < b.N; i++ {
		func() {
			// Fresh harness per iteration so each reconnect starts clean.
			h := newTunnelHarness(b, globalServerBin, globalClientBin, reconnectEnv)
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

			const maxWait = 15 * time.Second // 3s keepalive + handshake; 15s is ample
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

				if wErr == nil && rErr == nil && pong[0] == 0x42 {
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

// TestReconnect verifies the client automatically recovers after the server
// restarts. Uses fast 1s/3s keepalive so detection is quick.
func TestReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping reconnect test in short mode")
	}

	reconnectEnv := map[string]string{
		"DNSTT_SMUX_KEEPALIVE_INTERVAL": "1s",
		"DNSTT_SMUX_KEEPALIVE_TIMEOUT":  "3s",
	}
	h := newTunnelHarness(t, globalServerBin, globalClientBin, reconnectEnv)

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

	// Poll until a successful echo is achieved (3s keepalive + handshake; 15s ample).
	restartTime := time.Now()
	deadline := time.Now().Add(15 * time.Second)
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

		if wErr == nil && rErr == nil && pong[0] == 0x42 {
			reconnected = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	elapsed := time.Since(restartTime)
	if !reconnected {
		t.Fatal("failed to reconnect within 15s after server restart")
	}
	t.Logf("Reconnected in %v", elapsed)
	writeMetricsJSON(t, "reconnect.json", map[string]any{
		"reconnect_ms": elapsed.Milliseconds(),
	})
}
