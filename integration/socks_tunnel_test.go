//go:build integration

package integration_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"dnsttEx/noise"

	"golang.org/x/net/proxy"
)

// newSocksTunnelHarness starts dnstt-server in -tunnel socks mode and dnstt-client
// with -tunnel socks (SOCKS5 on ClientAddr). The server dials targets chosen by
// the client; the in-process echo server is the intended CONNECT target.
func newSocksTunnelHarness(t *testing.T, serverBin, clientBin string) *tunnelHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	realnet := loadRealNetworkConfig(t)
	if realnet != nil {
		t.Skip("socks tunnel harness does not support DNSTT_REALNET in this test")
	}

	h := &tunnelHarness{
		serverBin: serverBin,
		clientBin: clientBin,
		domain:    "socks.t.test.invalid",
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	h.echoLn = echoLn
	go runEchoServer(echoLn)

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatalf("GeneratePrivkey: %v", err)
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)
	h.privkeyHex = noise.EncodeKey(privkey)
	h.pubkeyHex = noise.EncodeKey(pubkey)

	h.dnsUDPAddr = allocFreeUDPAddr(t)
	clientResolverAddr := h.dnsUDPAddr

	h.serverCmd = exec.Command(serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		"-tunnel", "socks",
		h.domain,
	)
	h.serverCmd.Stderr = os.Stderr
	if err := h.serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	h.ClientAddr = allocFreeTCPAddr(t)

	h.clientCmd = exec.Command(clientBin,
		"-udp", clientResolverAddr,
		"-pubkey", h.pubkeyHex,
		"-tunnel", "socks",
		h.domain,
		h.ClientAddr,
	)
	h.clientCmd.Stderr = os.Stderr
	if err := h.clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}

	waitTCP(t, h.ClientAddr, 30*time.Second)
	t.Cleanup(func() { h.Teardown() })
	return h
}

// maxMTUForSpeedtest is the server -mtu value used for speed tests to maximize
// throughput (largest DNS response payload). 4096 is a safe large value.
const maxMTUForSpeedtest = 4096

// speedtestRelay is the common interface for relays used in speedtests (counting or delayed).
type speedtestRelay interface {
	Addr() string
	Close()
	Sent() int64
	Received() int64
}

// newSocksTunnelHarnessWithMaxMTU starts the same stack as newSocksTunnelHarness
// but with the largest MTU to measure peak throughput: server -mtu maxMTUForSpeedtest,
// a transparent UDP relay between client and server (so MTU discovery finds max
// response size), and client -mtu 255 (max QNAME length) to avoid request-path limits.
// Use for integration speed tests (e.g. 1MB download via SOCKS).
func newSocksTunnelHarnessWithMaxMTU(t *testing.T, serverBin, clientBin string) (speedtestRelay, *tunnelHarness) {
	t.Helper()
	return newSocksTunnelHarnessWithMaxMTUAndRTT(t, serverBin, clientBin, 0)
}

// newSocksTunnelHarnessWithMaxMTUAndRTT is like newSocksTunnelHarnessWithMaxMTU but
// when rtt > 0 uses a relay that delays each packet by rtt/2 in each direction
// (effective RTT = rtt). Use to reproduce real-world slow throughput (e.g. ~2 KB/s
// when tunnel MTU is small and RTT is high).
func newSocksTunnelHarnessWithMaxMTUAndRTT(t *testing.T, serverBin, clientBin string, rtt time.Duration) (speedtestRelay, *tunnelHarness) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	realnet := loadRealNetworkConfig(t)
	if realnet != nil {
		t.Skip("socks tunnel harness does not support DNSTT_REALNET in this test")
	}

	h := &tunnelHarness{
		serverBin: serverBin,
		clientBin: clientBin,
		domain:    "socks.t.test.invalid",
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	h.echoLn = echoLn
	go runEchoServer(echoLn)

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatalf("GeneratePrivkey: %v", err)
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)
	h.privkeyHex = noise.EncodeKey(privkey)
	h.pubkeyHex = noise.EncodeKey(pubkey)

	h.dnsUDPAddr = allocFreeUDPAddr(t)
	var relay speedtestRelay
	if rtt > 0 {
		relay = newDelayedCountingUDPRelay(t, h.dnsUDPAddr, rtt/2)
	} else {
		relay = newCountingUDPRelay(t, h.dnsUDPAddr)
	}
	clientResolverAddr := relay.Addr()

	h.serverCmd = exec.Command(serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		"-mtu", fmt.Sprintf("%d", maxMTUForSpeedtest),
		"-tunnel", "socks",
		h.domain,
	)
	h.serverCmd.Stderr = os.Stderr
	if err := h.serverCmd.Start(); err != nil {
		relay.Close()
		t.Fatalf("start server: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	h.ClientAddr = allocFreeTCPAddr(t)

	// -mtu 255: use max QNAME length so only server response size is discovered (faster, max throughput).
	clientEnv := map[string]string{
		"DNSTT_MTU_PROBE_TIMEOUT": "3s",
	}
	if rtt > 0 {
		clientEnv["DNSTT_MTU_PROBE_TIMEOUT"] = "10s"
	}
	h.clientCmd = exec.Command(clientBin,
		"-udp", clientResolverAddr,
		"-pubkey", h.pubkeyHex,
		"-mtu", "255",
		"-tunnel", "socks",
		h.domain,
		h.ClientAddr,
	)
	h.clientCmd.Stderr = os.Stderr
	env := os.Environ()
	for k, v := range clientEnv {
		env = append(env, k+"="+v)
	}
	h.clientCmd.Env = env
	if err := h.clientCmd.Start(); err != nil {
		relay.Close()
		h.Teardown()
		t.Fatalf("start client: %v", err)
	}

	waitDeadline := 45 * time.Second
	if rtt > 0 {
		waitDeadline = 90 * time.Second
	}
	waitTCP(t, h.ClientAddr, waitDeadline)
	t.Cleanup(func() {
		relay.Close()
		h.Teardown()
	})
	return relay, h
}

// TestSocksTunnelTCP runs SOCKS5 CONNECT through the client; the server dials the echo target.
func TestSocksTunnelTCP(t *testing.T) {
	h := newSocksTunnelHarness(t, globalServerBin, globalClientBin)

	dialer, err := proxy.SOCKS5("tcp", h.ClientAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5 dialer: %v", err)
	}
	echoAddr := h.EchoListenAddr()
	if echoAddr == "" {
		t.Fatal("no echo address")
	}
	conn, err := dialer.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("CONNECT via SOCKS to %s: %v", echoAddr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	payload := []byte("socks-tunnel-mode-hello")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q vs %q", got, payload)
	}
	t.Logf("SOCKS → tunnel → server dial → echo OK (%d bytes)", len(payload))
}

// runSpeedtestServer listens on ln and for each connection writes size bytes then closes.
// Used to measure download speed through the SOCKS tunnel (1MB file).
func runSpeedtestServer(ln net.Listener, size int) {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			// Write full payload (may take multiple writes).
			for n := 0; n < len(payload); {
				written, err := c.Write(payload[n:])
				if err != nil {
					return
				}
				n += written
			}
		}(conn)
	}
}

// TestSocksSpeedtest1MB downloads 1MB through the SOCKS tunnel with largest MTU
func TestSocksSpeedtest1MB(t *testing.T) {
	runSocksSpeedtest1MB(t, 0, 5*time.Minute, true)
}

// TestSocksSpeedtest1MBWithLatency runs the same 1MB download but with simulated RTT
func TestSocksSpeedtest1MBWithLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping latency speedtest in short mode")
	}
	const rtt = 3 * time.Second
	runSocksSpeedtest1MB(t, rtt, 10*time.Minute, false)
}

func runSocksSpeedtest1MB(t *testing.T, rtt time.Duration, timeout time.Duration, failIfSlow bool) {
	const downloadSize = 1 * 1024 * 1024 // 1 MB

	// 1. In-process server that sends 1MB on connect (like a file download).
	speedtestLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("speedtest server listen: %v", err)
	}
	defer speedtestLn.Close()
	go runSpeedtestServer(speedtestLn, downloadSize)
	speedtestAddr := speedtestLn.Addr().String()

	// 2. SOCKS tunnel with largest MTU; optional RTT simulation (delayed relay).
	var relay speedtestRelay
	var h *tunnelHarness
	if rtt > 0 {
		relay, h = newSocksTunnelHarnessWithMaxMTUAndRTT(t, globalServerBin, globalClientBin, rtt)
		t.Logf("Simulated RTT: %v (one-way delay %v)", rtt, rtt/2)
	} else {
		relay, h = newSocksTunnelHarnessWithMaxMTU(t, globalServerBin, globalClientBin)
	}

	// 3. Dial via SOCKS to our speedtest server and download 1MB.
	dialer, err := proxy.SOCKS5("tcp", h.ClientAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("SOCKS5 dialer: %v", err)
	}
	conn, err := dialer.Dial("tcp", speedtestAddr)
	if err != nil {
		t.Fatalf("CONNECT via SOCKS to %s: %v", speedtestAddr, err)
	}
	defer conn.Close()

	// 4. Read exactly 1MB and measure elapsed time.
	buf := make([]byte, downloadSize)
	conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	n, err := io.ReadFull(conn, buf)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("read 1MB: %v (got %d bytes)", err, n)
	}
	if n != downloadSize {
		t.Fatalf("read %d bytes, want %d", n, downloadSize)
	}

	// 5. Report speed (KiB/s and KB/s).
	elapsedSec := elapsed.Seconds()
	if elapsedSec <= 0 {
		elapsedSec = 1e-9
	}
	bytesPerSec := float64(downloadSize) / elapsedSec
	kibPerSec := bytesPerSec / 1024
	kbPerSec := bytesPerSec / 1000
	label := "max MTU, zero RTT"
	if rtt > 0 {
		label = fmt.Sprintf("max MTU, simulated RTT %v", rtt)
	}
	t.Logf("1MB download via SOCKS (%s): %v elapsed → %.2f KiB/s (%.2f KB/s) %.3f Mbps effective",
		label, elapsed.Round(time.Millisecond), kibPerSec, kbPerSec, (bytesPerSec*8)/1e6)
	t.Logf("DNS wire: client→server %d bytes, server→client %d bytes", relay.Sent(), relay.Received())

	if failIfSlow {
		const minReasonableKiBps = 5
		if kibPerSec < minReasonableKiBps {
			t.Errorf("throughput %.2f KiB/s is below minimum %d KiB/s — possible regression (compare with dnstt)", kibPerSec, minReasonableKiBps)
		}
	}
}
