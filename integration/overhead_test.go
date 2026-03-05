//go:build integration

package integration_test

import (
	"io"
	"testing"
	"time"
)

// TestOverhead measures the ratio of DNS wire bytes to application payload bytes.
// The DNS tunnel must base32-encode every packet into query labels and wrap it
// in DNS TXT RR responses, so the overhead is significant (typically 3–8×).
//
// Wire bytes are counted by countingUDPRelay, which sits transparently between
// the dnstt-client and dnstt-server subprocesses.
func TestOverhead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping overhead test in short mode")
	}

	relay, h := newTunnelHarnessWithRelay(t, globalServerBin, globalClientBin)
	conn := h.dialTunnel(t)
	defer conn.Close()

	const payloadBytes = 64 * 1024 // 64 KB per direction
	payload := make([]byte, payloadBytes)
	recvBuf := make([]byte, payloadBytes)

	conn.SetDeadline(time.Now().Add(120 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, recvBuf); err != nil {
		t.Fatalf("read: %v", err)
	}

	// Wait for KCP ACK packets to clear before snapshotting counters.
	time.Sleep(2 * time.Second)

	wireSent := relay.sent.Load()
	wireRecv := relay.received.Load()
	totalWire := wireSent + wireRecv
	// Both directions of application payload (sent + echoed back).
	totalPayload := int64(payloadBytes * 2)

	ratio := float64(totalWire) / float64(totalPayload)

	t.Logf("Wire bytes:    client→server=%d  server→client=%d  total=%d", wireSent, wireRecv, totalWire)
	t.Logf("Payload bytes: %d per direction, %d total", payloadBytes, totalPayload)
	t.Logf("Overhead ratio: %.2fx", ratio)

	writeMetricsJSON(t, "overhead.json", map[string]any{
		"wire_bytes_client_to_server": wireSent,
		"wire_bytes_server_to_client": wireRecv,
		"wire_bytes_total":            totalWire,
		"payload_bytes_per_direction": payloadBytes,
		"payload_bytes_total":         totalPayload,
		"overhead_ratio":              ratio,
	})

	// Sanity bounds: DNS tunnel overhead should be between 2× and 25×.
	// Lower bound: even with perfect packing, base32 + DNS framing adds ≥2×.
	// Upper bound: if overhead exceeds 25×, something is badly wrong.
	if ratio < 2.0 {
		t.Errorf("overhead ratio %.2f is suspiciously low (expected ≥ 2.0)", ratio)
	}
	if ratio > 25.0 {
		t.Errorf("overhead ratio %.2f is too high (expected ≤ 25.0)", ratio)
	}
}
