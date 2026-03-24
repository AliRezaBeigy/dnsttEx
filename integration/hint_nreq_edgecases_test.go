//go:build integration

package integration_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func roundTripPayload(t *testing.T, conn net.Conn, size int, deadline time.Duration) {
	t.Helper()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte((i*31 + 7) % 256)
	}
	conn.SetDeadline(time.Now().Add(deadline))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload(%d): %v", size, err)
	}
	recv := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read payload(%d): %v", size, err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatalf("echo mismatch for payload size=%d", size)
	}
}

// Hint poll + NREQ on a clean DNS path: verifies periodic hint probes do not
// break normal delivery. We do not assert full payload recovery under
// bidirectional packet loss — that is not guaranteed and would be a flaky or
// misleading test (see network_hardening_test.go for lossy paths).
func TestHintPollAndNREQCleanPathEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping edge-case hint poll test in short mode")
	}
	t.Setenv("DNSTT_HINT_POLL_MS", "500")
	t.Setenv("DNSTT_KCP_NREQ", "1")
	clientEnv := map[string]string{
		"DNSTT_MTU_PROBE_TIMEOUT": "1s",
		"DNSTT_SEND_CHANNEL_SIZE": "1310720",
	}
	h := newTunnelHarnessWithRelayAndStderr(
		t,
		globalServerBin,
		globalClientBin,
		func(addr string) udpRelay {
			return newCountingUDPRelay(t, addr)
		},
		&bytes.Buffer{},
		clientEnv,
	)
	conn := h.dialTunnel(t)
	defer conn.Close()
	// Enough volume that several hint-timer ticks overlap with tunnel traffic.
	roundTripPayload(t, conn, 32*1024, 60*time.Second)
}

func TestHintPollIntervalEdgeValues(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping hint interval edge test in short mode")
	}
	cases := []struct {
		name         string
		hintPollMs   string
		payloadBytes int
	}{
		{name: "below_min_clamped", hintPollMs: "1", payloadBytes: 8 * 1024},
		{name: "above_max_clamped", hintPollMs: "999999", payloadBytes: 8 * 1024},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DNSTT_HINT_POLL_MS", tc.hintPollMs)
			t.Setenv("DNSTT_KCP_NREQ", "1")
			clientEnv := map[string]string{
				"DNSTT_MTU_PROBE_TIMEOUT": "1s",
			}
			h := newTunnelHarnessWithRelayAndStderr(
				t,
				globalServerBin,
				globalClientBin,
				func(addr string) udpRelay {
					// Add duplicate/delay noise while keeping path recoverable.
					return newChaosUDPRelay(t, addr, 0, 0, 4, 100*time.Millisecond)
				},
				&bytes.Buffer{},
				clientEnv,
			)
			conn := h.dialTunnel(t)
			defer conn.Close()
			roundTripPayload(t, conn, tc.payloadBytes, 60*time.Second)
		})
	}
}

// Edge case: overlapping NREQ windows with high NREQ/replay copies should not
// break stream delivery or cause payload corruption.
func TestOverlappingNREQWithHighCopiesStillDelivers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping overlap/copies edge test in short mode")
	}
	t.Setenv("DNSTT_KCP_NREQ", "1")
	t.Setenv("DNSTT_KCP_NREQ_COPIES", "4")
	t.Setenv("DNSTT_KCP_REPLAY_SEND_COPIES", "4")
	t.Setenv("DNSTT_HINT_POLL_MS", "500")
	clientEnv := map[string]string{
		"DNSTT_MTU_PROBE_TIMEOUT": "1s",
		"DNSTT_SEND_CHANNEL_SIZE": "1310720",
	}
	h := newTunnelHarnessWithRelayAndStderr(
		t,
		globalServerBin,
		globalClientBin,
		func(addr string) udpRelay {
			// Induce many resend opportunities + duplicates.
			return newChaosUDPRelay(t, addr, 9, 7, 3, 120*time.Millisecond)
		},
		&bytes.Buffer{},
		clientEnv,
	)
	conn := h.dialTunnel(t)
	defer conn.Close()
	roundTripPayload(t, conn, 32*1024, 120*time.Second)
}

