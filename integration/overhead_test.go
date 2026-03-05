//go:build integration

package integration_test

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// TestOverhead measures the ratio of DNS wire bytes to application payload bytes.
// Name-based uses Base36 (0-9a-v, 8/5 expansion), case-insensitive decode for QNAME randomization; overhead ~3×.
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
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	recvBuf := make([]byte, payloadBytes)

	conn.SetDeadline(time.Now().Add(120 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, recvBuf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, recvBuf) {
		t.Fatal("echoed data does not match sent data (corruption or truncation)")
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

	// Sanity bounds: ratio must be at least 1.0 (wire ≥ payload) and not absurdly high.
	if ratio < 1.0 {
		t.Errorf("overhead ratio %.2f is impossible (wire < payload)", ratio)
	}
	if ratio > 25.0 {
		t.Errorf("overhead ratio %.2f is too high (expected ≤ 25.0)", ratio)
	}
}
