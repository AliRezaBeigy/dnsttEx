//go:build integration

package integration_test

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// TestMTUDiscoveryFullPath verifies that with a transparent relay the client runs
// MTU discovery and reports a large downstream MTU and max question QNAME length 255 (RFC max).
func TestMTUDiscoveryFullPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MTU discovery test in short mode")
	}
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay { return newCountingUDPRelay(t, addr) },
		&stderrBuf, nil)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 10*time.Second)
	if serverMTU < 512 {
		t.Errorf("server MTU %d < 512 (expected at least 512 with transparent path)", serverMTU)
	}
	if clientMTU != 255 {
		t.Errorf("client MTU %d != 255 (max question QNAME wire length)", clientMTU)
	}
	t.Logf("MTU discovery: server=%d client=%d", serverMTU, clientMTU)

	// Quick echo to confirm tunnel works with discovered MTU.
	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	payload := []byte("mtu-test")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	recv := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("echo mismatch")
	}
}

// TestMTUDiscoveryTruncated512 verifies that when the path truncates responses to 512 bytes,
// the client discovers server MTU 512 while the request-side MTU stays at the
// normal DNS query ceiling, and the tunnel still works for small transfers.
func TestMTUDiscoveryTruncated512(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MTU discovery test in short mode")
	}
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay { return newTruncatingUDPRelay(t, addr, 512) },
		&stderrBuf, nil)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if serverMTU != 512 {
		t.Errorf("with 512-byte truncating relay: server MTU = %d, want 512", serverMTU)
	}
	if clientMTU != 255 {
		t.Errorf("client MTU = %d, want 255 (response truncation should not reduce QNAME MTU)", clientMTU)
	}
	t.Logf("MTU discovery (512 relay): server=%d client=%d", serverMTU, clientMTU)

	// Tunnel must still work with 512-byte responses (small payload to finish quickly).
	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(90 * time.Second))
	const smallPayload = 256
	payload := make([]byte, smallPayload)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	recv := make([]byte, smallPayload)
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("echo mismatch")
	}
	t.Logf("%d-byte echo OK over 512-byte path", smallPayload)
}
