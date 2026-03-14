//go:build integration

package integration_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"dnsttEx/noise"
)

// runSocks5Proxy accepts connections on ln and handles SOCKS5 CONNECT requests,
// relaying traffic bidirectionally between the client and the target host.
func runSocks5Proxy(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSocks5(conn)
	}
}

func handleSocks5(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 258)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dLen]); err != nil {
			return
		}
		host = string(buf[:dLen])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	remote, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{})
	go func() {
		io.Copy(remote, conn)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(conn, remote)
	<-done
}

// TestSocks5RealCurl runs an actual `curl -x socks5h://...` command through the
// full dnstt tunnel stack with a DNS relay in the middle and a SOCKS5 proxy on
// the server side.
//
// Architecture (every arrow is a real network hop):
//
//	curl -x socks5h://client_addr http://ipify.ir
//	  → dnstt-client  (TCP → DNS encoding)
//	    → counting UDP relay with DNS logging
//	      → dnstt-server  (DNS decoding → TCP)
//	        → in-process SOCKS5 proxy
//	          → ipify.ir  (internet)
//
// Requires: curl in PATH, internet access. Skipped otherwise.
// Flaky: skipped by default; set RUN_FLAKY_TESTS=1 to run.
func TestSocks5RealCurl(t *testing.T) {
	if os.Getenv("RUN_FLAKY_TESTS") != "1" {
		t.Skip("skipping flaky test (set RUN_FLAKY_TESTS=1 to run)")
	}
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("skipping: curl not found in PATH")
	}

	probe, err := net.DialTimeout("tcp", "ipify.ir:80", 5*time.Second)
	if err != nil {
		t.Skipf("skipping: ipify.ir unreachable (%v)", err)
	}
	probe.Close()

	// 1. In-process SOCKS5 proxy (server-side upstream).
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	defer socksLn.Close()
	go runSocks5Proxy(socksLn)
	t.Logf("SOCKS5 proxy listening on %s", socksLn.Addr())

	// 2. Noise keypair.
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatalf("GeneratePrivkey: %v", err)
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)
	privkeyHex := noise.EncodeKey(privkey)
	pubkeyHex := noise.EncodeKey(pubkey)

	dnsUDPAddr := allocFreeUDPAddr(t)
	domain := "t.test.invalid"

	// 3. dnstt-server → SOCKS5 proxy.
	serverCmd := exec.Command(globalServerBin,
		"-udp", dnsUDPAddr,
		"-privkey", privkeyHex,
		domain,
		socksLn.Addr().String(),
	)
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		serverCmd.Process.Kill()
		serverCmd.Wait()
	}()
	time.Sleep(300 * time.Millisecond)
	t.Logf("dnstt-server listening on UDP %s → upstream %s", dnsUDPAddr, socksLn.Addr())

	// 4. Counting UDP relay with DNS wire logging between client and server.
	relay := newCountingUDPRelayWithDNSLog(t, dnsUDPAddr, t)
	defer relay.Close()
	t.Logf("DNS relay on %s → server %s", relay.Addr(), dnsUDPAddr)

	// 5. dnstt-client → relay.
	clientAddr := allocFreeTCPAddr(t)
	clientCmd := exec.Command(globalClientBin,
		"-udp", relay.Addr(),
		"-pubkey", pubkeyHex,
		domain,
		clientAddr,
	)
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer func() {
		clientCmd.Process.Kill()
		clientCmd.Wait()
	}()

	waitTCP(t, clientAddr, 20*time.Second)
	t.Logf("dnstt-client listening on %s (SOCKS5 entry point)", clientAddr)

	// 6. Run real curl through the tunnel.
	t.Logf("running: %s -x socks5h://%s --max-time 45 -s http://ipify.ir", curlPath, clientAddr)
	curlCmd := exec.Command(curlPath,
		"-x", "socks5h://"+clientAddr,
		"--max-time", "45",
		"-s", "-S",
		"http://ipify.ir",
	)
	curlOut, err := curlCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed: %v\noutput: %s", err, curlOut)
	}

	body := strings.TrimSpace(string(curlOut))
	t.Logf("curl response (%d bytes): %s", len(body), body)

	if len(body) == 0 {
		t.Fatal("curl returned empty body")
	}

	t.Logf("DNS wire stats: client→server %d bytes, server→client %d bytes",
		relay.sent.Load(), relay.received.Load())
	t.Log("TestSocks5RealCurl: OK — real curl through dnstt tunnel via SOCKS5")
}

// TestSocks5RealCurlSlowLossy is like TestSocks5RealCurl but runs the tunnel over
// a slow, lossy, low-MTU path (128-byte client MTU, 512-byte server MTU, ~80ms
// one-way delay, ~6.7% client→server packet loss). Verifies that real curl
// through SOCKS5 still succeeds when some queries never reach the server.
// Flaky: skipped by default; set RUN_FLAKY_TESTS=1 to run.
func TestSocks5RealCurlSlowLossy(t *testing.T) {
	if os.Getenv("RUN_FLAKY_TESTS") != "1" {
		t.Skip("skipping flaky test (set RUN_FLAKY_TESTS=1 to run)")
	}
	if testing.Short() {
		t.Skip("skipping slow+lossy curl test in short mode")
	}

	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("skipping: curl not found in PATH")
	}

	probe, err := net.DialTimeout("tcp", "ipify.ir:80", 5*time.Second)
	if err != nil {
		t.Skipf("skipping: ipify.ir unreachable (%v)", err)
	}
	probe.Close()

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	defer socksLn.Close()
	go runSocks5Proxy(socksLn)
	t.Logf("SOCKS5 proxy listening on %s", socksLn.Addr())

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatalf("GeneratePrivkey: %v", err)
	}
	privkeyHex := noise.EncodeKey(privkey)
	pubkeyHex := noise.EncodeKey(noise.PubkeyFromPrivkey(privkey))

	dnsUDPAddr := allocFreeUDPAddr(t)
	domain := "t.test.invalid"

	serverCmd := exec.Command(globalServerBin,
		"-udp", dnsUDPAddr,
		"-privkey", privkeyHex,
		domain,
		socksLn.Addr().String(),
	)
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		serverCmd.Process.Kill()
		serverCmd.Wait()
	}()
	time.Sleep(300 * time.Millisecond)
	t.Logf("dnstt-server listening on UDP %s → upstream %s", dnsUDPAddr, socksLn.Addr())

	const maxResponseSize = 512
	const maxClientQueryWireFor128Tier = 129 // max QNAME octets (DPI-style); not UDP payload
	const serverDelay = 80 * time.Millisecond
	const dropClientEvery = 15

	relay := newSlowLossyTruncatingUDPRelay(t, dnsUDPAddr, maxResponseSize, maxClientQueryWireFor128Tier, serverDelay, dropClientEvery)
	defer relay.Close()
	t.Logf("DNS relay (slow+lossy, MTU 512/128, delay=%v, drop every %d) on %s → server %s", serverDelay, dropClientEvery, relay.Addr(), dnsUDPAddr)

	clientAddr := allocFreeTCPAddr(t)
	clientCmd := exec.Command(globalClientBin,
		"-udp", relay.Addr(),
		"-pubkey", pubkeyHex,
		domain,
		clientAddr,
	)
	clientCmd.Stderr = os.Stderr
	clientCmd.Env = append(os.Environ(), "DNSTT_MTU_PROBE_TIMEOUT=2s", "DNSTT_SEND_CHANNEL_SIZE=1310720")
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	defer func() {
		clientCmd.Process.Kill()
		clientCmd.Wait()
	}()

	waitTCP(t, clientAddr, 30*time.Second)
	t.Logf("dnstt-client listening on %s (SOCKS5 entry point)", clientAddr)

	t.Logf("running: %s -x socks5h://%s --max-time 120 -s http://ipify.ir (slow+lossy path)", curlPath, clientAddr)
	curlCmd := exec.Command(curlPath,
		"-x", "socks5h://"+clientAddr,
		"--max-time", "120",
		"-s", "-S",
		"http://ipify.ir",
	)
	curlOut, err := curlCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed on slow+lossy path: %v\noutput: %s", err, curlOut)
	}

	body := strings.TrimSpace(string(curlOut))
	t.Logf("curl response (%d bytes): %s", len(body), body)

	if len(body) == 0 {
		t.Fatal("curl returned empty body")
	}

	t.Logf("client→server packets: %d (slow+lossy)", relay.sent.Load())
	t.Log("TestSocks5RealCurlSlowLossy: OK — real curl through dnstt tunnel via SOCKS5 over slow+lossy path")
}
