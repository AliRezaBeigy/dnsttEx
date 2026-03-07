//go:build integration

package integration_test

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// TestLargeTransfer verifies the tunnel correctly handles large request and response
// payloads. It sends a large payload (256 KB) in each direction and checks integrity.
// This ensures the stack works with large application-level transfers that span many
// DNS queries/responses (chunking, reassembly, no truncation or corruption).
func TestLargeTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large transfer test in short mode")
	}

	_, h := newTunnelHarnessWithRelay(t, globalServerBin, globalClientBin)
	conn := h.dialTunnel(t)
	defer conn.Close()

	const payloadBytes = 256 * 1024 // 256 KB per direction
	payload := make([]byte, payloadBytes)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	recvBuf := make([]byte, payloadBytes)

	conn.SetDeadline(time.Now().Add(180 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, recvBuf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, recvBuf) {
		t.Fatal("echoed data does not match sent data (corruption or truncation)")
	}

	t.Logf("large transfer OK: %d bytes per direction (%d total) with full integrity",
		payloadBytes, payloadBytes*2)
}
