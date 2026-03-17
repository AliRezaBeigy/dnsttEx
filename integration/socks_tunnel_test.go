//go:build integration

package integration_test

import (
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
