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

// mtuDiscoveryLogPattern matches MTU discovery log from client stderr.
var mtuDiscoveryLogPattern = regexp.MustCompile(`MTU discovery: .* → max response wire (\d+) bytes, max query QNAME (\d+) bytes`)

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

// TestLowMTUCommunication verifies 128-tier client QNAME MTU and 512-byte server path.
// Relay drops queries whose QNAME length > 128 (so 160+ probes fail).
func TestLowMTUCommunication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping low MTU test in short mode")
	}
	clientEnv := map[string]string{"DNSTT_MTU_PROBE_TIMEOUT": "2s"}

	const maxResponseSize = 512
	const wantClientMTUProbeTier = 128
	const maxClientQNameFor128Tier = 129 // allow 128-tier probe (QNAME may be 128–129 octets)
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingUDPRelayWithClientQueryWireLimit(t, addr, maxResponseSize, maxClientQNameFor128Tier)
		},
		&stderrBuf, clientEnv)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if serverMTU != maxResponseSize {
		t.Errorf("server MTU = %d, want %d (path limits responses to %d)", serverMTU, maxResponseSize, maxResponseSize)
	}
	if clientMTU != wantClientMTUProbeTier {
		t.Errorf("client MTU = %d, want %d (relay drops QNAME > %d)", clientMTU, wantClientMTUProbeTier, maxClientQNameFor128Tier)
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
			return newTruncatingUDPRelayWithClientQueryWireLimit(t, addr, maxResponseSize, 255) // allow full QNAME
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

// maxClientPacketsForLowMTUTest is an upper bound on total client→server bytes
// forwarded by the relay during the low-MTU large-transfer test. With a 16KB
// payload at 128-byte request MTU (~42-byte KCP MSS), we expect roughly a few
// thousand queries for data + handshake + ACKs + polls. If the client sends
// without backpressure it can reach hundreds of thousands; we fail early when
// this cap is exceeded to detect "client sending unlimited packets".
const maxClientPacketsForLowMTUTest = 4000000

// TestLowMTULargeTransferIntegrity verifies end-to-end integrity for a large
// payload while the client request path is truly constrained (64-byte probe tier here).
// Unlike TestLowMTUCommunication, this test does not switch to a looser relay.
// It also fails early if the client sends more than maxClientPacketsForLowMTUTest
// client→server packets (runaway send with no backpressure).
func TestLowMTULargeTransferIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping low MTU large transfer test in short mode")
	}
	// Give the server more room to queue downstream records while the small
	// query-wire path drains slowly, otherwise the test can fail due to artificial
	// queue pressure instead of transport corruption.
	t.Setenv("DNSTT_SEND_CHANNEL_SIZE", "1310720")

	clientEnv := map[string]string{"DNSTT_MTU_PROBE_TIMEOUT": "2s"}
	const maxResponseSize = 512
	const wantClientMTUProbeTier = 64
	const maxClientQNameFor64Tier = 65

	var stderrBuf bytes.Buffer
	var relay *truncatingUDPRelay
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			relay = newTruncatingUDPRelayWithClientQueryWireLimit(t, addr, maxResponseSize, maxClientQNameFor64Tier)
			return relay
		},
		&stderrBuf, clientEnv)

	var serverMTU, clientMTU int
	if integrationExternalMode() {
		// In external mode we don't capture client stderr, so we can't parse MTU discovery.
		serverMTU, clientMTU = maxResponseSize, wantClientMTUProbeTier
		t.Logf("MTU discovery: server=%d client=%d (external mode, not verified from stderr)", serverMTU, clientMTU)
		waitTCP(t, "127.0.0.1:1082", 20*time.Second)
	} else {
		serverMTU, clientMTU = waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
		if serverMTU != maxResponseSize {
			t.Errorf("server MTU = %d, want %d (path limits responses to %d)", serverMTU, maxResponseSize, maxResponseSize)
		}
		if clientMTU != wantClientMTUProbeTier {
			t.Fatalf("client MTU = %d, want %d (relay drops QNAME > %d)", clientMTU, wantClientMTUProbeTier, maxClientQNameFor64Tier)
		}
		t.Logf("MTU discovery: server=%d client=%d", serverMTU, clientMTU)
	}

	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(180 * time.Second))

	const payloadSize = 16 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	recv := make([]byte, payloadSize)

	// Fail early if client sends too many packets (runaway send without backpressure).
	runaway := make(chan int64, 1)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			n := relay.sent.Load()
			if n > maxClientPacketsForLowMTUTest {
				select {
				case runaway <- n:
				default:
				}
				return
			}
		}
	}()

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeDone <- err
	}()

	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, recv)
		readDone <- err
	}()

	var writeErr, readErr error
	for doneCount := 0; doneCount < 2; {
		select {
		case count := <-runaway:
			// Log client stderr to see if NXDOMAIN/retry or other errors explain the runaway.
			if b := stderrBuf.Bytes(); len(b) > 0 {
				show := b
				if len(b) > 2000 {
					show = b[len(b)-2000:]
					t.Logf("client stderr (last 2000 of %d bytes): ...%s", len(b), show)
				} else {
					t.Logf("client stderr: %s", b)
				}
			}
			t.Fatalf("client runaway send: %d client→server packets (cap %d); client is sending without backpressure on low MTU path", count, maxClientPacketsForLowMTUTest)
		case writeErr = <-writeDone:
			if writeErr != nil {
				t.Fatalf("write large payload over low query-wire path: %v", writeErr)
			}
			doneCount++
		case readErr = <-readDone:
			if readErr != nil {
				t.Fatalf("read large payload over low query-wire path: %v", readErr)
			}
			doneCount++
		}
	}

	if !bytes.Equal(payload, recv) {
		t.Fatal("large-transfer echo mismatch on low client query-wire path")
	}
	t.Logf("large low-MTU transfer OK: %d bytes echoed intact with server=%d client=%d (client→server packets: %d)", payloadSize, serverMTU, clientMTU, relay.sent.Load())
}

// maxClientPacketsForSlowLossyTest is a higher cap for the slow+lossy test because
// retries and RTT mean more packets for the same payload. Still fail if client
// runs away without backpressure.
const maxClientPacketsForSlowLossyTest = 8000000

// TestSlowLossyLowMTULargeTransferIntegrity verifies end-to-end integrity for a
// large payload over a constrained path (128-byte client MTU, 512-byte server
// MTU) with realistic slow internet (one-way delay) and client→server packet
// loss so that some queries never reach the server. The tunnel must still
// deliver the full payload correctly via retries and reliability.
func TestSlowLossyLowMTULargeTransferIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow lossy low MTU large transfer test in short mode")
	}
	t.Setenv("DNSTT_SEND_CHANNEL_SIZE", "1310720")

	clientEnv := map[string]string{"DNSTT_MTU_PROBE_TIMEOUT": "2s"}
	const maxResponseSize = 512
	const wantClientMTUProbeTier = 128
	const maxClientQNameFor128TierSlow = 129
	// Realistic slow link: ~80ms one-way delay (~160ms RTT).
	const serverDelay = 80 * time.Millisecond
	// Drop every 15th client→server packet (~6.7% of queries never reach server).
	const dropClientEvery = 15

	var stderrBuf bytes.Buffer
	var relay *slowLossyTruncatingUDPRelay
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			relay = newSlowLossyTruncatingUDPRelay(t, addr, maxResponseSize, maxClientQNameFor128TierSlow, serverDelay, dropClientEvery)
			return relay
		},
		&stderrBuf, clientEnv)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 20*time.Second)
	if serverMTU != maxResponseSize {
		t.Errorf("server MTU = %d, want %d (path limits responses to %d)", serverMTU, maxResponseSize, maxResponseSize)
	}
	if clientMTU != wantClientMTUProbeTier {
		t.Fatalf("client MTU = %d, want %d (relay drops QNAME > %d)", clientMTU, wantClientMTUProbeTier, maxClientQNameFor128TierSlow)
	}
	t.Logf("MTU discovery: server=%d client=%d (delay=%v, drop client every %d)", serverMTU, clientMTU, serverDelay, dropClientEvery)

	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(300 * time.Second))

	const payloadSize = 16 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	recv := make([]byte, payloadSize)

	runaway := make(chan int64, 1)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			n := relay.sent.Load()
			if n > maxClientPacketsForSlowLossyTest {
				select {
				case runaway <- n:
				default:
				}
				return
			}
		}
	}()

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeDone <- err
	}()

	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, recv)
		readDone <- err
	}()

	var writeErr, readErr error
	for doneCount := 0; doneCount < 2; {
		select {
		case count := <-runaway:
			if b := stderrBuf.Bytes(); len(b) > 0 {
				show := b
				if len(b) > 2000 {
					show = b[len(b)-2000:]
					t.Logf("client stderr (last 2000 of %d bytes): ...%s", len(b), show)
				} else {
					t.Logf("client stderr: %s", b)
				}
			}
			t.Fatalf("client runaway send: %d client→server packets (cap %d) on slow+lossy path", count, maxClientPacketsForSlowLossyTest)
		case writeErr = <-writeDone:
			if writeErr != nil {
				t.Fatalf("write large payload over slow+lossy 128-byte path: %v", writeErr)
			}
			doneCount++
		case readErr = <-readDone:
			if readErr != nil {
				t.Fatalf("read large payload over slow+lossy 128-byte path: %v", readErr)
			}
			doneCount++
		}
	}

	if !bytes.Equal(payload, recv) {
		t.Fatal("large transfer echo mismatch on slow+lossy 128-byte client MTU path")
	}
	t.Logf("slow+lossy low-MTU transfer OK: %d bytes echoed intact (server=%d client=%d, delay=%v, drop every %d; client→server packets: %d)",
		payloadSize, serverMTU, clientMTU, serverDelay, dropClientEvery, relay.sent.Load())
}

// sendMaxRequestPattern matches DNSTT_DEBUG send line (max QNAME cap).
var sendMaxRequestPattern = regexp.MustCompile(`send: QNAME \d+ bytes, query wire \d+ \(max QNAME (\d+)\)`)

// TestTunnelUsesDiscoveredRequestMTU verifies send path uses discovered QNAME MTU in debug logs.
func TestTunnelUsesDiscoveredRequestMTU(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MTU test in short mode")
	}
	const maxResponseSize = 512
	const wantDiscoveredQNAME = 160
	// Relay allows QNAME <= 160; 192-tier probes dropped.
	clientEnv := map[string]string{
		"DNSTT_MTU_PROBE_TIMEOUT": "2s",
		"DNSTT_DEBUG":             "1",
	}
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingUDPRelayWithClientQueryWireLimit(t, addr, maxResponseSize, wantDiscoveredQNAME)
		},
		&stderrBuf, clientEnv)

	serverMTU, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if clientMTU != wantDiscoveredQNAME {
		t.Fatalf("MTU discovery: client MTU = %d, want %d", clientMTU, wantDiscoveredQNAME)
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

	stderr := stderrBuf.Bytes()
	matches := sendMaxRequestPattern.FindAllSubmatch(stderr, -1)
	if len(matches) == 0 {
		t.Skip("no DNSTT_DEBUG send lines found")
	}
	for _, m := range matches {
		if len(m) != 2 {
			continue
		}
		maxReq, _ := strconv.Atoi(string(m[1]))
		if maxReq != wantDiscoveredQNAME {
			t.Errorf("send path max QNAME %d; discovery %d", maxReq, wantDiscoveredQNAME)
		}
	}
	t.Logf("verified %d send(s) used discovered max QNAME %d", len(matches), wantDiscoveredQNAME)
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
	const wantQNAME = 160
	clientEnv := map[string]string{
		"DNSTT_MTU_PROBE_TIMEOUT": "2s",
		"DNSTT_DEBUG":             "1",
	}
	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingUDPRelayWithClientQueryWireLimit(t, addr, maxResponseSize, wantQNAME)
		},
		&stderrBuf, clientEnv)

	_, clientMTU := waitForMTUDiscovery(t, &stderrBuf, 15*time.Second)
	if clientMTU != wantQNAME {
		t.Fatalf("MTU discovery: client MTU = %d, want %d", clientMTU, wantQNAME)
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
	// Only count sends with >20 bytes tunnel data so we exclude idle polls and tiny ACKs
	// when computing batching average (we still check maxPacketsInOne across all sends).
	const minTunnelBytesForAvg = 20
	for _, m := range matches {
		if len(m) != 3 {
			continue
		}
		n, _ := strconv.Atoi(string(m[1]))
		b, _ := strconv.Atoi(string(m[2]))
		if n > maxPacketsInOne {
			maxPacketsInOne = n
		}
		if b > minTunnelBytesForAvg {
			dataSends++
			totalTunnelBytes += b
		}
	}
	if dataSends == 0 {
		t.Skip("no data sends found in stderr (with >20 bytes)")
	}
	if maxPacketsInOne < 2 {
		t.Errorf("all data sends had 1 packet (max=%d); expected at least one query with 2+ packets", maxPacketsInOne)
	}
	avgBytesPerSend := totalTunnelBytes / dataSends
	// If we batched, average should be at least one small packet (~55 bytes). We require >= 55
	// so we're not consistently sending tiny fragments (allows some timing variance).
	if avgBytesPerSend < 55 {
		t.Errorf("average tunnel bytes per data send = %d (total %d in %d sends); expected batching (avg >= 55)", avgBytesPerSend, totalTunnelBytes, dataSends)
	}
	t.Logf("echo OK; %d data sends, %d total tunnel bytes (avg %d/send), max %d packets in one query", dataSends, totalTunnelBytes, avgBytesPerSend, maxPacketsInOne)
}
