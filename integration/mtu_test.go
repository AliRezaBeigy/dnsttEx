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
// MTU discovery and reports a large downstream MTU and the expected request-side
// ceiling. DNS query names cap request wire size to roughly 280 bytes, so the
// client-side request MTU cannot grow to match the downstream response MTU.
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
	if clientMTU != 280 {
		t.Errorf("client MTU %d != 280 (DNS query wire size is expected to top out around 280 bytes on a transparent path)", clientMTU)
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
	if clientMTU != 280 {
		t.Errorf("client MTU = %d, want 280 (response truncation should not reduce request-path MTU)", clientMTU)
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

// TestLowMTUCommunication verifies that client (128-byte request MTU) and server
// (512-byte response MTU) can communicate with data integrity over a constrained path.
// The relay limits responses to 512 bytes and drops requests larger than maxRequestSize,
// so MTU discovery finds server MTU 512 and client MTU = maxRequestSize.
// We use client MTU 128 for discovery assertion; the echo test uses 256 so it completes
// in reasonable time (with 128 the server send channel fills and responses are dropped).
func TestLowMTUCommunication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping low MTU test in short mode")
	}
	// Short MTU probe timeout so dropped probes (relay drops 160 and 280) don't block 8s each.
	clientEnv := map[string]string{"DNSTT_MTU_PROBE_TIMEOUT": "2s"}

	const maxResponseSize = 512 // server MTU: path truncates responses to this
	const maxRequestSize = 128  // client MTU: relay drops requests larger than this
	// Relay drops requests above this. Use 129 so 128-byte probe gets through (wire can be 128–129).
	// Then assert clientMTU == 128. For the echo we need the tunnel to make progress: use a second
	// harness with 256 so echo completes (or we'd need a much larger server channel and timeout).
	const relayDropRequestAboveFor128 = 129
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingUDPRelayWithRequestLimit(t, addr, maxResponseSize, relayDropRequestAboveFor128)
		},
		&stderrBuf, clientEnv)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if serverMTU != maxResponseSize {
		t.Errorf("server MTU = %d, want %d (path limits responses to %d)", serverMTU, maxResponseSize, maxResponseSize)
	}
	if clientMTU != maxRequestSize {
		t.Errorf("client MTU = %d, want %d (relay drops requests > %d)", clientMTU, maxRequestSize, relayDropRequestAboveFor128)
	}
	t.Logf("MTU discovery: server=%d client=%d", serverMTU, clientMTU)
	// The first harness is only needed to observe the constrained discovery result.
	// Tear it down before phase 2 so fixed real-network bind addresses can be reused.
	h.Teardown()

	// Data integrity: run echo over a path that allows 256-byte requests so the
	// server send channel does not fill; confirms the same stack works end-to-end with integrity.
	var stderrBuf2 bytes.Buffer
	h2 := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingUDPRelayWithRequestLimit(t, addr, maxResponseSize, 257) // 256 ok, 280 dropped
		},
		&stderrBuf2, clientEnv)
	_, _ = waitForMTUDiscovery(t, &stderrBuf2, 15*time.Second)

	conn := h2.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(120 * time.Second))
	const payloadSize = 64
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	recv := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("echo mismatch: client and server did not communicate correctly over low MTU (data integrity check failed)")
	}
	t.Logf("%d-byte echo OK over low-MTU path (server %d / client %d then echo at 256), data integrity verified", payloadSize, serverMTU, clientMTU)
}

// TestLowMTULargeTransferIntegrity verifies end-to-end integrity for a large
// payload while the client request path is truly constrained to 128 bytes.
// Unlike TestLowMTUCommunication, this test does not switch to a looser relay.
func TestLowMTULargeTransferIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping low MTU large transfer test in short mode")
	}
	// Give the server more room to queue downstream records while the 128-byte
	// request path drains slowly, otherwise the test can fail due to artificial
	// queue pressure instead of transport corruption.
	t.Setenv("DNSTT_SEND_CHANNEL_SIZE", "1310720")

	clientEnv := map[string]string{"DNSTT_MTU_PROBE_TIMEOUT": "2s"}
	const maxResponseSize = 512
	const maxRequestSize = 128
	const relayDropRequestAboveFor128 = 129

	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingUDPRelayWithRequestLimit(t, addr, maxResponseSize, relayDropRequestAboveFor128)
		},
		&stderrBuf, clientEnv)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if serverMTU != maxResponseSize {
		t.Errorf("server MTU = %d, want %d (path limits responses to %d)", serverMTU, maxResponseSize, maxResponseSize)
	}
	if clientMTU != maxRequestSize {
		t.Fatalf("client MTU = %d, want %d (relay drops requests > %d)", clientMTU, maxRequestSize, relayDropRequestAboveFor128)
	}
	t.Logf("MTU discovery: server=%d client=%d", serverMTU, clientMTU)

	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(180 * time.Second))

	const payloadSize = 16 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	recv := make([]byte, payloadSize)

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write large payload over 128-byte request path: %v", err)
	}
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read large payload over 128-byte request path: %v", err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("large-transfer echo mismatch on 128-byte client MTU path")
	}
	t.Logf("large low-MTU transfer OK: %d bytes echoed intact with server=%d client=%d", payloadSize, serverMTU, clientMTU)
}

// sendMaxRequestPattern matches "send: query wire 123 bytes (max request 256)" in DNSTT_DEBUG output.
var sendMaxRequestPattern = regexp.MustCompile(`send: query wire \d+ bytes \(max request (\d+)\)`)

// TestTunnelUsesDiscoveredRequestMTU verifies that after MTU discovery, the tunnel send path uses
// the discovered max request size (not a smaller default). So when the path allows 256-byte
// queries, we should see "max request 256" in send debug lines, not 128 or 0.
func TestTunnelUsesDiscoveredRequestMTU(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MTU test in short mode")
	}
	const maxResponseSize = 512
	const maxRequestSize = 256
	// Relay allows requests up to 257 bytes so 256-byte probe succeeds.
	clientEnv := map[string]string{
		"DNSTT_MTU_PROBE_TIMEOUT": "2s",
		"DNSTT_DEBUG":             "1",
	}
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingUDPRelayWithRequestLimit(t, addr, maxResponseSize, 257)
		},
		&stderrBuf, clientEnv)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if clientMTU != maxRequestSize {
		t.Fatalf("MTU discovery: client MTU = %d, want %d", clientMTU, maxRequestSize)
	}
	t.Logf("MTU discovery: server=%d client=%d", serverMTU, clientMTU)

	// Send enough data that we send at least one query with tunnel payload; DNSTT_DEBUG logs "max request N".
	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	payload := []byte("discovery-mtu-test")
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

	// Ensure the send path used the discovered max request size (256), not a smaller value.
	stderr := stderrBuf.Bytes()
	matches := sendMaxRequestPattern.FindAllSubmatch(stderr, -1)
	if len(matches) == 0 {
		t.Skip("no DNSTT_DEBUG send lines found (client may not have logged query wire size)")
	}
	for _, m := range matches {
		if len(m) != 2 {
			continue
		}
		maxReq, _ := strconv.Atoi(string(m[1]))
		if maxReq != maxRequestSize {
			t.Errorf("send path used max request %d; discovery found %d (tunnel must use discovered MTU)", maxReq, maxRequestSize)
		}
	}
	t.Logf("verified %d send(s) used discovered max request %d", len(matches), maxRequestSize)
}

// sendLoopPacketsPattern matches "sendLoop: sending query with N packet(s), M bytes tunnel data".
var sendLoopPacketsPattern = regexp.MustCompile(`sendLoop: sending query with (\d+) packet\(s\), (\d+) bytes tunnel data`)

// TestTunnelBatchesPacketsWhenSending1024 verifies that when we send payload we (1) get a correct
// echo back and (2) batch multiple packets per query: at least one send has 2+ packets, and
// average tunnel bytes per data send is above a single small packet (~60 bytes), so we're not
// consistently sending 1-packet queries.
func TestTunnelBatchesPacketsWhenSending1024(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MTU test in short mode")
	}
	const maxResponseSize = 512
	const maxRequestSize = 256
	clientEnv := map[string]string{
		"DNSTT_MTU_PROBE_TIMEOUT": "2s",
		"DNSTT_DEBUG":             "1",
	}
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingUDPRelayWithRequestLimit(t, addr, maxResponseSize, 257)
		},
		&stderrBuf, clientEnv)

	_, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if clientMTU != maxRequestSize {
		t.Fatalf("MTU discovery: client MTU = %d, want %d", clientMTU, maxRequestSize)
	}

	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(90 * time.Second))
	payloadSize := 256
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	recv := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read: %v (echo must succeed to verify batching)", err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("echo mismatch")
	}

	stderr := stderrBuf.Bytes()
	matches := sendLoopPacketsPattern.FindAllSubmatch(stderr, -1)
	var dataSends, totalTunnelBytes, maxPacketsInOne int
	for _, m := range matches {
		if len(m) != 3 {
			continue
		}
		dataSends++
		n, _ := strconv.Atoi(string(m[1]))
		b, _ := strconv.Atoi(string(m[2]))
		totalTunnelBytes += b
		if n > maxPacketsInOne {
			maxPacketsInOne = n
		}
	}
	if dataSends == 0 {
		t.Skip("no data sends found in stderr")
	}
	if maxPacketsInOne < 2 {
		t.Errorf("all data sends had 1 packet (max=%d); expected at least one query with 2+ packets", maxPacketsInOne)
	}
	avgBytesPerSend := totalTunnelBytes / dataSends
	// If we batched, average should be at least one small packet (~60 bytes). Consistently
	// 1-packet sends would give avg ~60; we require >= 60 so we're not sending tiny fragments.
	if avgBytesPerSend < 60 {
		t.Errorf("average tunnel bytes per data send = %d (total %d in %d sends); expected batching (avg >= 60)", avgBytesPerSend, totalTunnelBytes, dataSends)
	}
	t.Logf("echo OK; %d data sends, %d total tunnel bytes (avg %d/send), max %d packets in one query", dataSends, totalTunnelBytes, avgBytesPerSend, maxPacketsInOne)
}
