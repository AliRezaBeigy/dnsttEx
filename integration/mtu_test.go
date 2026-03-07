//go:build integration

package integration_test

import (
	"bytes"
	"io"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// mtuDiscoveryLogPattern matches "MTU discovery: 127.0.0.1:12345 → max response 4096 bytes, max request 512 bytes".
var mtuDiscoveryLogPattern = regexp.MustCompile(`MTU discovery: .* → max response (\d+) bytes, max request (\d+) bytes`)

// parseMTUDiscoveryFromStderr reads stderrBuf and returns (serverMTU, clientMTU, true) if a line matches.
// Returns (0, 0, false) if not found.
func parseMTUDiscoveryFromStderr(stderrBuf *bytes.Buffer) (serverMTU, clientMTU int, ok bool) {
	sub := mtuDiscoveryLogPattern.FindSubmatch(stderrBuf.Bytes())
	if len(sub) != 3 {
		return 0, 0, false
	}
	serverMTU, _ = strconv.Atoi(string(sub[1]))
	clientMTU, _ = strconv.Atoi(string(sub[2]))
	return serverMTU, clientMTU, true
}

// waitForMTUDiscovery polls stderrBuf for the MTU discovery log line until timeout.
func waitForMTUDiscovery(t testing.TB, stderrBuf *bytes.Buffer, timeout time.Duration) (serverMTU, clientMTU int) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s, c, ok := parseMTUDiscoveryFromStderr(stderrBuf); ok {
			return s, c
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("did not see MTU discovery log line in client stderr within %v", timeout)
	return 0, 0
}

// TestMTUDiscoveryFullPath verifies that with a transparent relay the client runs
// MTU discovery and reports server and client MTU >= 512 (path supports at least 512).
func TestMTUDiscoveryFullPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MTU discovery test in short mode")
	}
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay { return newCountingUDPRelay(t, addr) },
		&stderrBuf)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 10*time.Second)
	if serverMTU < 512 {
		t.Errorf("server MTU %d < 512 (expected at least 512 with transparent path)", serverMTU)
	}
	if clientMTU < 512 {
		t.Errorf("client MTU %d < 512 (expected at least 512 with transparent path)", clientMTU)
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
// the client discovers server MTU 512 and the tunnel still works (small transfers).
func TestMTUDiscoveryTruncated512(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MTU discovery test in short mode")
	}
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay { return newTruncatingUDPRelay(t, addr, 512) },
		&stderrBuf)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if serverMTU != 512 {
		t.Errorf("with 512-byte truncating relay: server MTU = %d, want 512", serverMTU)
	}
	if clientMTU < 512 {
		t.Errorf("client MTU %d < 512", clientMTU)
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
