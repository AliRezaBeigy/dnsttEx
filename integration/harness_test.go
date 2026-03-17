//go:build integration

package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dnsttEx/dns"
	"dnsttEx/noise"
)

// integrationDNSQuestionQNameWireLen is the length in octets of the first question QNAME on the wire.
func integrationDNSQuestionQNameWireLen(msg []byte) (int, bool) {
	if len(msg) < 13 {
		return 0, false
	}
	i := 12
	for i < len(msg) {
		l := int(msg[i])
		if l == 0 {
			return i - 12 + 1, true
		}
		if l&0xC0 == 0xC0 || l > 63 {
			return 0, false
		}
		i += 1 + l
		if i > len(msg) {
			return 0, false
		}
	}
	return 0, false
}

var (
	globalServerBin string
	globalClientBin string
)

func TestMain(m *testing.M) {
	if os.Getenv("DNSTT_INTEGRATION_PRINT_KEYS") == "1" {
		privkey, err := noise.GeneratePrivkey()
		if err != nil {
			log.Fatalf("GeneratePrivkey: %v", err)
		}
		pubkey := noise.PubkeyFromPrivkey(privkey)
		fmt.Printf("DNSTT_INTEGRATION_PRIVKEY=%s\n", noise.EncodeKey(privkey))
		fmt.Printf("DNSTT_INTEGRATION_PUBKEY=%s\n", noise.EncodeKey(pubkey))
		fmt.Fprintf(os.Stderr, "Add these to your Server/Client/Test launch config env for DNSTT_INTEGRATION_EXTERNAL=1 debugging.\n")
		os.Exit(0)
	}

	dir, err := os.MkdirTemp("", "dnstt-int-*")
	if err != nil {
		log.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(thisFile)) // parent of integration/ = project root

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	pairs := [][2]string{
		{filepath.Join(dir, "dnsttEx-server"+ext), filepath.Join(root, "dnsttEx-server")},
		{filepath.Join(dir, "dnsttEx-client"+ext), filepath.Join(root, "dnsttEx-client")},
	}
	for _, p := range pairs {
		cmd := exec.Command("go", "build", "-o", p[0], p[1])
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("build %s: %v\n%s", filepath.Base(p[1]), err, out)
		}
	}

	globalServerBin = pairs[0][0]
	globalClientBin = pairs[1][0]

	os.Exit(m.Run())
}

// tunnelHarness manages a complete in-process tunnel for testing:
//   - an in-process TCP echo server
//   - a dnstt-server subprocess
//   - a dnstt-client subprocess
type tunnelHarness struct {
	// ClientAddr is the TCP address the dnstt-client listens on.
	// Dial this address to send data through the tunnel.
	ClientAddr string

	// Stored for reconnect tests (restart server on same port with same key).
	dnsUDPAddr string
	privkeyHex string
	pubkeyHex  string
	domain     string

	serverBin string
	clientBin string

	serverCmd *exec.Cmd
	clientCmd *exec.Cmd
	echoLn    net.Listener
}

type realNetworkConfig struct {
	ServerBind   string
	ServerTarget string
	ClientListen string
}

func realNetworkEnabled() bool {
	return os.Getenv("DNSTT_REALNET") != ""
}

func validateUDPBindAddr(t testing.TB, addr string, envName string) {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("%s %q is not a valid UDP address: %v", envName, addr, err)
	}
	probeAddr := *udpAddr
	probeAddr.Port = 0
	ln, err := net.ListenUDP("udp", &probeAddr)
	if err != nil {
		t.Fatalf("%s %q is not bindable on this machine: %v\nUse a local interface address or 0.0.0.0:port for binding, and use DNSTT_REALNET_SERVER_TARGET for the client-facing address.", envName, addr, err)
	}
	ln.Close()
}

func validateTCPListenAddr(t testing.TB, addr string, envName string) {
	t.Helper()
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatalf("%s %q is not a valid TCP address: %v", envName, addr, err)
	}
	probeAddr := *tcpAddr
	probeAddr.Port = 0
	ln, err := net.ListenTCP("tcp", &probeAddr)
	if err != nil {
		t.Fatalf("%s %q is not listenable on this machine: %v", envName, addr, err)
	}
	ln.Close()
}

func loadRealNetworkConfig(t testing.TB) *realNetworkConfig {
	t.Helper()
	if !realNetworkEnabled() {
		return nil
	}
	cfg := &realNetworkConfig{
		ServerBind:   os.Getenv("DNSTT_REALNET_SERVER_BIND"),
		ServerTarget: os.Getenv("DNSTT_REALNET_SERVER_TARGET"),
		ClientListen: os.Getenv("DNSTT_REALNET_CLIENT_LISTEN"),
	}
	if cfg.ServerBind == "" {
		t.Fatal("DNSTT_REALNET=1 requires DNSTT_REALNET_SERVER_BIND")
	}
	if cfg.ServerTarget == "" {
		t.Fatal("DNSTT_REALNET=1 requires DNSTT_REALNET_SERVER_TARGET")
	}
	if cfg.ClientListen == "" {
		cfg.ClientListen = allocFreeTCPAddr(t)
	}
	validateUDPBindAddr(t, cfg.ServerBind, "DNSTT_REALNET_SERVER_BIND")
	validateTCPListenAddr(t, cfg.ClientListen, "DNSTT_REALNET_CLIENT_LISTEN")
	return cfg
}

// externalIntegrationPorts are used when DNSTT_INTEGRATION_EXTERNAL=1 so that
// server and client can be started under the debugger with fixed launch configs.
const (
	externalRelayListen  = "127.0.0.1:9353"
	externalServerUDP    = "127.0.0.1:9354"
	externalClientListen = "127.0.0.1:1082"
	externalEchoListen   = "127.0.0.1:9090"
)

func integrationExternalMode() bool {
	return os.Getenv("DNSTT_INTEGRATION_EXTERNAL") == "1"
}

func relayListenUDPAddr(t testing.TB) *net.UDPAddr {
	t.Helper()
	addr := "127.0.0.1:0"
	if realNetworkEnabled() {
		addr = "0.0.0.0:0"
	}
	if integrationExternalMode() {
		addr = externalRelayListen
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve relay listen addr: %v", err)
	}
	return udpAddr
}

func relayAdvertiseAddr(t testing.TB, listenAddr string, serverAddrStr string) string {
	t.Helper()
	if !realNetworkEnabled() {
		return listenAddr
	}
	host, _, err := net.SplitHostPort(serverAddrStr)
	if err != nil {
		t.Fatalf("split relay server addr: %v", err)
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		t.Fatalf("split relay listen addr: %v", err)
	}
	return net.JoinHostPort(host, port)
}

func relayUpstreamBindAddr(listenAddr *net.UDPAddr) *net.UDPAddr {
	if listenAddr == nil {
		return nil
	}
	return &net.UDPAddr{IP: listenAddr.IP, Port: 0, Zone: listenAddr.Zone}
}

// newTunnelHarness starts a full tunnel stack and waits for it to be ready.
// Registers t.Cleanup(h.Teardown). If clientEnv is non-nil, the client process
// is started with those env vars (e.g. DNSTT_SMUX_KEEPALIVE_TIMEOUT for reconnect tests).
func newTunnelHarness(t testing.TB, serverBin, clientBin string, clientEnv map[string]string) *tunnelHarness {
	t.Helper()
	realnet := loadRealNetworkConfig(t)

	h := &tunnelHarness{
		serverBin: serverBin,
		clientBin: clientBin,
		domain:    "t.test.invalid",
	}

	// 1. In-process echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	h.echoLn = echoLn
	go runEchoServer(echoLn)

	// 2. Generate keypair via noise library (importable — not package main).
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatalf("GeneratePrivkey: %v", err)
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)
	h.privkeyHex = noise.EncodeKey(privkey)
	h.pubkeyHex = noise.EncodeKey(pubkey)

	// 3. DNS server bind address.
	clientResolverAddr := ""
	if realnet != nil {
		h.dnsUDPAddr = realnet.ServerBind
		clientResolverAddr = realnet.ServerTarget
	} else {
		h.dnsUDPAddr = allocFreeUDPAddr(t)
		clientResolverAddr = h.dnsUDPAddr
	}

	// 4. Start dnstt-server.
	h.serverCmd = exec.Command(serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		"-tunnel", "tcp",
		h.domain,
		echoLn.Addr().String(),
	)
	h.serverCmd.Stderr = os.Stderr
	if err := h.serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	// Give server time to bind its UDP socket.
	time.Sleep(300 * time.Millisecond)

	// 5. Client listener address.
	if realnet != nil {
		h.ClientAddr = realnet.ClientListen
	} else {
		h.ClientAddr = allocFreeTCPAddr(t)
	}

	// 6. Start dnstt-client.
	h.clientCmd = exec.Command(clientBin,
		"-udp", clientResolverAddr,
		"-pubkey", h.pubkeyHex,
		"-tunnel", "tcp",
		h.domain,
		h.ClientAddr,
	)
	h.clientCmd.Stderr = os.Stderr
	if len(clientEnv) > 0 {
		env := os.Environ()
		for k, v := range clientEnv {
			env = append(env, k+"="+v)
		}
		h.clientCmd.Env = env
	}
	if err := h.clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}

	// 7. Wait until client TCP port accepts connections.
	waitTCP(t, h.ClientAddr, 20*time.Second)

	t.Cleanup(func() { h.Teardown() })
	return h
}

// newTunnelHarnessWithRelay is like newTunnelHarness but interposes a
// countingUDPRelay between client and server to measure wire bytes.
func newTunnelHarnessWithRelay(t testing.TB, serverBin, clientBin string) (*countingUDPRelay, *tunnelHarness) {
	t.Helper()
	realnet := loadRealNetworkConfig(t)

	h := &tunnelHarness{
		serverBin: serverBin,
		clientBin: clientBin,
		domain:    "t.test.invalid",
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

	clientResolverAddr := ""
	if realnet != nil {
		h.dnsUDPAddr = realnet.ServerBind
		clientResolverAddr = realnet.ServerTarget
	} else {
		h.dnsUDPAddr = allocFreeUDPAddr(t)
		clientResolverAddr = h.dnsUDPAddr
	}

	h.serverCmd = exec.Command(serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		"-tunnel", "tcp",
		h.domain,
		echoLn.Addr().String(),
	)
	h.serverCmd.Stderr = os.Stderr
	if err := h.serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Insert counting relay between client and server.
	var relay *countingUDPRelay
	if realnet != nil {
		relay = newRealNetworkCountingUDPRelay(t, clientResolverAddr, nil)
	} else {
		relay = newCountingUDPRelay(t, h.dnsUDPAddr)
	}

	if realnet != nil {
		h.ClientAddr = realnet.ClientListen
	} else {
		h.ClientAddr = allocFreeTCPAddr(t)
	}
	h.clientCmd = exec.Command(clientBin,
		"-udp", relay.Addr(), // client → relay → server
		"-pubkey", h.pubkeyHex,
		"-tunnel", "tcp",
		h.domain,
		h.ClientAddr,
	)
	h.clientCmd.Stderr = os.Stderr
	if err := h.clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}

	waitTCP(t, h.ClientAddr, 20*time.Second)

	t.Cleanup(func() {
		relay.Close()
		h.Teardown()
	})
	return relay, h
}

// udpRelay is the interface used by harnesses that sit client and server (counting or truncating).
type udpRelay interface {
	Addr() string
	Close()
}

// makeRelayFunc creates a relay given the server UDP address (so the relay can forward to the server).
type makeRelayFunc func(serverAddr string) udpRelay

// newTunnelHarnessWithRelayAndStderr is like newTunnelHarnessWithRelay but uses
// makeRelay(serverAddr) to create the relay after the server is started, and
// captures client stderr into stderrBuf so tests can parse e.g. "MTU discovery ... server=512 client=512".
// If clientEnv is non-nil, the client process is started with these env vars (in addition to the current process env).
//
// When DNSTT_INTEGRATION_EXTERNAL=1, the harness does not start server or client; it only starts
// the in-process echo server and relay on fixed ports (see external* constants). Start server and
// client under the debugger using the same keypair and ports. Set DNSTT_INTEGRATION_PRIVKEY and
// DNSTT_INTEGRATION_PUBKEY in the environment (run TestPrintIntegrationKeys with
// DNSTT_INTEGRATION_PRINT_KEYS=1 to generate a keypair).
func newTunnelHarnessWithRelayAndStderr(t testing.TB, serverBin, clientBin string, makeRelay makeRelayFunc, stderrBuf *bytes.Buffer, clientEnv map[string]string) *tunnelHarness {
	t.Helper()
	if integrationExternalMode() {
		return newTunnelHarnessExternalWithRelayAndStderr(t, makeRelay, stderrBuf)
	}
	realnet := loadRealNetworkConfig(t)
	h := &tunnelHarness{
		serverBin: serverBin,
		clientBin: clientBin,
		domain:    "t.test.invalid",
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
	h.privkeyHex = noise.EncodeKey(privkey)
	h.pubkeyHex = noise.EncodeKey(noise.PubkeyFromPrivkey(privkey))
	clientResolverAddr := ""
	if realnet != nil {
		h.dnsUDPAddr = realnet.ServerBind
		clientResolverAddr = realnet.ServerTarget
	} else {
		h.dnsUDPAddr = allocFreeUDPAddr(t)
		clientResolverAddr = h.dnsUDPAddr
	}
	h.serverCmd = exec.Command(serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		"-tunnel", "tcp",
		h.domain,
		echoLn.Addr().String(),
	)
	h.serverCmd.Stderr = os.Stderr
	if err := h.serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	relay := makeRelay(clientResolverAddr)
	if realnet != nil {
		h.ClientAddr = realnet.ClientListen
	} else {
		h.ClientAddr = allocFreeTCPAddr(t)
	}
	h.clientCmd = exec.Command(clientBin,
		"-udp", relay.Addr(),
		"-pubkey", h.pubkeyHex,
		"-tunnel", "tcp",
		h.domain,
		h.ClientAddr,
	)
	h.clientCmd.Stderr = io.MultiWriter(os.Stderr, stderrBuf)
	if len(clientEnv) > 0 {
		env := os.Environ()
		for k, v := range clientEnv {
			env = append(env, k+"="+v)
		}
		h.clientCmd.Env = env
	}
	if err := h.clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	waitTCP(t, h.ClientAddr, 20*time.Second)
	t.Cleanup(func() {
		relay.Close()
		h.Teardown()
	})
	return h
}

// newTunnelHarnessExternalWithRelayAndStderr is used when DNSTT_INTEGRATION_EXTERNAL=1.
// It starts only the echo server and relay on fixed ports; server and client must be
// started separately (e.g. under the debugger) with the same keypair and ports.
func newTunnelHarnessExternalWithRelayAndStderr(t testing.TB, makeRelay makeRelayFunc, stderrBuf *bytes.Buffer) *tunnelHarness {
	t.Helper()
	privkeyHex := os.Getenv("DNSTT_INTEGRATION_PRIVKEY")
	pubkeyHex := os.Getenv("DNSTT_INTEGRATION_PUBKEY")
	if privkeyHex == "" || pubkeyHex == "" {
		t.Fatalf("DNSTT_INTEGRATION_EXTERNAL=1 requires DNSTT_INTEGRATION_PRIVKEY and DNSTT_INTEGRATION_PUBKEY in environment. Run TestPrintIntegrationKeys with DNSTT_INTEGRATION_PRINT_KEYS=1 to generate a keypair, then set those env vars in your Server and Client launch configs.")
	}
	h := &tunnelHarness{
		domain:     "t.test.invalid",
		privkeyHex: privkeyHex,
		pubkeyHex:  pubkeyHex,
		dnsUDPAddr: externalServerUDP,
		ClientAddr: externalClientListen,
		serverCmd:  nil,
		clientCmd:  nil,
	}
	echoLn, err := net.Listen("tcp", externalEchoListen)
	if err != nil {
		t.Fatalf("echo listen (external mode): %v (is another process using %s?)", err, externalEchoListen)
	}
	h.echoLn = echoLn
	go runEchoServer(echoLn)
	relay := makeRelay(externalServerUDP)
	t.Logf("external mode: relay %s -> server %s; start server with -udp %s -privkey <same> %s %s; start client with -udp %s -pubkey <same> %s %s",
		externalRelayListen, externalServerUDP, externalServerUDP, h.domain, externalEchoListen, externalRelayListen, h.domain, externalClientListen)
	_ = stderrBuf
	t.Cleanup(func() {
		relay.Close()
		h.Teardown()
	})
	return h
}

// newTunnelHarnessWithRelayAndDNSLog is like newTunnelHarnessWithRelay but
// logs each DNS query and response via t.Logf.
func newTunnelHarnessWithRelayAndDNSLog(t testing.TB, serverBin, clientBin string) (*countingUDPRelay, *tunnelHarness) {
	t.Helper()
	realnet := loadRealNetworkConfig(t)

	h := &tunnelHarness{
		serverBin: serverBin,
		clientBin: clientBin,
		domain:    "t.test.invalid",
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

	clientResolverAddr := ""
	if realnet != nil {
		h.dnsUDPAddr = realnet.ServerBind
		clientResolverAddr = realnet.ServerTarget
	} else {
		h.dnsUDPAddr = allocFreeUDPAddr(t)
		clientResolverAddr = h.dnsUDPAddr
	}

	h.serverCmd = exec.Command(serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		"-tunnel", "tcp",
		h.domain,
		echoLn.Addr().String(),
	)
	h.serverCmd.Stderr = os.Stderr
	if err := h.serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	var relay *countingUDPRelay
	if realnet != nil {
		relay = newRealNetworkCountingUDPRelay(t, clientResolverAddr, t)
	} else {
		relay = newCountingUDPRelayWithDNSLog(t, h.dnsUDPAddr, t)
	}

	if realnet != nil {
		h.ClientAddr = realnet.ClientListen
	} else {
		h.ClientAddr = allocFreeTCPAddr(t)
	}
	h.clientCmd = exec.Command(clientBin,
		"-udp", relay.Addr(),
		"-pubkey", h.pubkeyHex,
		"-tunnel", "tcp",
		h.domain,
		h.ClientAddr,
	)
	h.clientCmd.Stderr = os.Stderr
	if err := h.clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}

	waitTCP(t, h.ClientAddr, 20*time.Second)

	t.Cleanup(func() {
		relay.Close()
		h.Teardown()
	})
	return relay, h
}

// EchoListenAddr returns the echo server address (127.0.0.1:port), for tests that
// dial the final target (e.g. SOCKS tunnel mode).
func (h *tunnelHarness) EchoListenAddr() string {
	if h.echoLn == nil {
		return ""
	}
	return h.echoLn.Addr().String()
}

// dialTunnel opens a TCP connection to the client's local listener.
func (h *tunnelHarness) dialTunnel(t testing.TB) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ClientAddr, 15*time.Second)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	return conn
}

// Teardown kills both subprocesses and closes the echo server.
func (h *tunnelHarness) Teardown() {
	if h.clientCmd != nil && h.clientCmd.Process != nil {
		h.clientCmd.Process.Kill()
		h.clientCmd.Wait()
	}
	if h.serverCmd != nil && h.serverCmd.Process != nil {
		h.serverCmd.Process.Kill()
		h.serverCmd.Wait()
	}
	if h.echoLn != nil {
		h.echoLn.Close()
	}
}

// runEchoServer accepts TCP connections and echoes all bytes back.
func runEchoServer(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c)
		}(conn)
	}
}

// signalOnFirstAcceptListener wraps a listener and closes ready when the first connection is accepted.
type signalOnFirstAcceptListener struct {
	net.Listener
	once  sync.Once
	ready chan struct{}
}

func (s *signalOnFirstAcceptListener) Accept() (net.Conn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	s.once.Do(func() { close(s.ready) })
	return conn, nil
}

// allocFreeUDPAddr returns a free loopback UDP host:port string.
func allocFreeUDPAddr(t testing.TB) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocFreeUDPAddr: %v", err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	return addr
}

// allocFreeTCPAddr returns a free loopback TCP host:port string.
func allocFreeTCPAddr(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocFreeTCPAddr: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// waitTCP polls addr until a TCP connection succeeds or timeout elapses.
func waitTCP(t testing.TB, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for TCP at %s", timeout, addr)
}

// pingPong sends one byte (0x42) and reads one byte back, asserting it matches (15s deadline).
func pingPong(t testing.TB, conn net.Conn, label string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte{0x42}); err != nil {
		t.Fatalf("%s write: %v", label, err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("%s read: %v", label, err)
	}
	if buf[0] != 0x42 {
		t.Fatalf("%s: echoed byte %x, want 0x42 (data corruption)", label, buf[0])
	}
}

// TestSanity verifies the harness works: starts the full stack and does a 1-byte echo.
func TestSanity(t *testing.T) {
	h := newTunnelHarness(t, globalServerBin, globalClientBin, nil)
	conn := h.dialTunnel(t)
	defer conn.Close()
	pingPong(t, conn, "sanity")
	t.Log("sanity echo OK")
}

// TestSanityUDPViaRelay verifies client and server communicate over UDP DNS when
// a relay sits between them (client → relay → server). This is a realistic
// UDP-only integration test: real DNS wire format over UDP, no DoH/DoT.
// DNS queries and responses are logged via t.Logf.
func TestSanityUDPViaRelay(t *testing.T) {
	relay, h := newTunnelHarnessWithRelayAndDNSLog(t, globalServerBin, globalClientBin)
	_ = relay
	conn := h.dialTunnel(t)
	defer conn.Close()
	pingPong(t, conn, "udp-via-relay")
	t.Log("UDP DNS via relay echo OK")
}

// TestDataIntegrity sends a deterministic payload through the tunnel and
// verifies the echo is byte-for-byte identical. Ensures data transmission
// is fully correct (no corruption, reordering, or truncation).
// Uses the relay-with-DNS-logging so DNS queries and responses are logged,
// including tunnel_payload size (EDNS 0xFF00/0xFF01) so you see real data in the log.
//
// Note: This tests real DNS wire format over UDP (client ↔ relay ↔ server on localhost).
// It does not run through the public DNS hierarchy (no recursive resolver, no NS delegation).
func TestDataIntegrity(t *testing.T) {
	relay, h := newTunnelHarnessWithRelayAndDNSLog(t, globalServerBin, globalClientBin)
	_ = relay
	conn := h.dialTunnel(t)
	defer conn.Close()

	// Deterministic payload: 16 KB, every byte unique and predictable.
	const size = 16 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	recvBuf := make([]byte, size)

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, recvBuf); err != nil {
		t.Fatalf("read: %v", err)
	}
	for i := range payload {
		if recvBuf[i] != payload[i] {
			t.Fatalf("data corruption at byte %d: got %x, want %x", i, recvBuf[i], payload[i])
		}
	}
	t.Logf("data integrity OK: %d bytes echoed correctly", size)
}

// --- countingUDPRelay ---

// countingUDPRelay is a transparent UDP middleman between client and server.
// It counts raw bytes in both directions for wire-overhead measurement.
// If dnsLog is set, each DNS packet is parsed and logged (query/response).
type countingUDPRelay struct {
	ln               *net.UDPConn // listens for client packets
	serverAddr       *net.UDPAddr // real server address
	upstreamBindAddr *net.UDPAddr
	advertiseAddr    string

	sent     atomic.Int64 // bytes forwarded client → server
	received atomic.Int64 // bytes forwarded server → client

	mu         sync.Mutex
	clientAddr *net.UDPAddr // last known client address (filled on first packet)

	done chan struct{}

	dnsLog testing.TB // if set, log DNS query/response via Logf
}

func newCountingUDPRelay(t testing.TB, serverAddrStr string) *countingUDPRelay {
	return newCountingUDPRelayWithDNSLog(t, serverAddrStr, nil)
}

// newCountingUDPRelayWithDNSLog is like newCountingUDPRelay but logs each DNS
// query and response via tb.Logf when dnsLog is non-nil.
func newCountingUDPRelayWithDNSLog(t testing.TB, serverAddrStr string, dnsLog testing.TB) *countingUDPRelay {
	if realNetworkEnabled() {
		return newRealNetworkCountingUDPRelay(t, serverAddrStr, dnsLog)
	}
	return newCountingUDPRelayWithConfig(t, serverAddrStr, dnsLog, "127.0.0.1:0", "")
}

// newRealNetworkCountingUDPRelay exposes a transparent relay on the same host as
// serverAddrStr so relay-based tests can still traverse a real interface.
func newRealNetworkCountingUDPRelay(t testing.TB, serverAddrStr string, dnsLog testing.TB) *countingUDPRelay {
	t.Helper()
	host, _, err := net.SplitHostPort(serverAddrStr)
	if err != nil {
		t.Fatalf("split real-network relay server target: %v", err)
	}
	return newCountingUDPRelayWithConfig(t, serverAddrStr, dnsLog, "0.0.0.0:0", host)
}

func newCountingUDPRelayWithConfig(t testing.TB, serverAddrStr string, dnsLog testing.TB, listenAddrStr string, advertiseHost string) *countingUDPRelay {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("resolve server addr: %v", err)
	}
	listenAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		t.Fatalf("resolve relay listen addr: %v", err)
	}
	ln, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	advertiseAddr := ln.LocalAddr().String()
	if advertiseHost != "" {
		_, port, err := net.SplitHostPort(advertiseAddr)
		if err != nil {
			ln.Close()
			t.Fatalf("split relay listen addr: %v", err)
		}
		advertiseAddr = net.JoinHostPort(advertiseHost, port)
	}
	r := &countingUDPRelay{
		ln:               ln,
		serverAddr:       serverAddr,
		upstreamBindAddr: &net.UDPAddr{IP: listenAddr.IP, Port: 0, Zone: listenAddr.Zone},
		advertiseAddr:    advertiseAddr,
		done:             make(chan struct{}),
		dnsLog:           dnsLog,
	}
	go r.loop()
	return r
}

// Addr returns the UDP address clients should send queries to.
func (r *countingUDPRelay) Addr() string {
	if r.advertiseAddr != "" {
		return r.advertiseAddr
	}
	return r.ln.LocalAddr().String()
}

// Close shuts down the relay.
func (r *countingUDPRelay) Close() {
	close(r.done)
	r.ln.Close()
}

func (r *countingUDPRelay) loop() {
	// Single goroutine: receive from ln, forward to server, receive server replies, forward to client.
	// We use a second UDPConn to talk to the server so we can ReadFrom both directions.
	serverConn, err := net.ListenUDP("udp", r.upstreamBindAddr)
	if err != nil {
		return
	}
	defer serverConn.Close()

	buf := make([]byte, 4096)

	// Goroutine: server → client
	go func() {
		buf2 := make([]byte, 4096)
		for {
			n, _, err := serverConn.ReadFromUDP(buf2)
			if err != nil {
				return
			}
			if r.dnsLog != nil {
				logDNSMessage(r.dnsLog, "response", buf2[:n])
			}
			r.received.Add(int64(n))
			r.mu.Lock()
			clientAddr := r.clientAddr
			r.mu.Unlock()
			if clientAddr != nil {
				r.ln.WriteToUDP(buf2[:n], clientAddr)
			}
		}
	}()

	// Main loop: client → server
	for {
		n, clientAddr, err := r.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if r.dnsLog != nil {
			logDNSMessage(r.dnsLog, "query", buf[:n])
		}
		r.sent.Add(int64(n))
		r.mu.Lock()
		r.clientAddr = clientAddr
		r.mu.Unlock()
		serverConn.WriteToUDP(buf[:n], r.serverAddr)
	}
}

// truncatingUDPRelay limits server→client DNS response wire to maxResponseSize bytes
// (UDP payload = DNS message). If maxRequestSize > 0, drops client→server datagrams
// whose question QNAME wire length exceeds it (DPI-style), not full UDP payload size.
type truncatingUDPRelay struct {
	ln              *net.UDPConn
	serverConn      *net.UDPConn
	serverAddr      *net.UDPAddr
	advertiseAddr   string
	maxResponseSize int // max DNS response wire bytes (UDP payload)
	maxRequestSize  int // max question QNAME wire octets; 0 = no limit
	sent            atomic.Int64
	received        atomic.Int64
	mu              sync.Mutex
	clientAddr      *net.UDPAddr
}

// newTruncatingUDPRelay creates a relay that truncates responses to maxResponseSize.
// Use newTruncatingUDPRelayWithRequestLimit to also limit request size (client MTU).
func newTruncatingUDPRelay(t testing.TB, serverAddrStr string, maxResponseSize int) *truncatingUDPRelay {
	return newTruncatingUDPRelayWithRequestLimit(t, serverAddrStr, maxResponseSize, 0)
}

// newTruncatingUDPRelayWithRequestLimit creates a relay that truncates DNS response wire
// to maxResponseSize and drops queries whose QNAME length > maxRequestSize.
// Pass maxRequestSize 0 for no query-name limit.
func newTruncatingUDPRelayWithRequestLimit(t testing.TB, serverAddrStr string, maxResponseSize, maxRequestSize int) *truncatingUDPRelay {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("resolve server addr: %v", err)
	}
	listenAddr := relayListenUDPAddr(t)
	ln, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		t.Fatalf("truncating relay listen: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", relayUpstreamBindAddr(listenAddr))
	if err != nil {
		ln.Close()
		t.Fatalf("truncating relay server conn: %v", err)
	}
	r := &truncatingUDPRelay{
		ln: ln, serverConn: serverConn, serverAddr: serverAddr,
		advertiseAddr:   relayAdvertiseAddr(t, ln.LocalAddr().String(), serverAddrStr),
		maxResponseSize: maxResponseSize,
		maxRequestSize:  maxRequestSize,
	}
	buf := make([]byte, 4096)
	go func() {
		buf2 := make([]byte, 4096)
		for {
			n, _, err := serverConn.ReadFromUDP(buf2)
			if err != nil {
				return
			}
			r.received.Add(int64(n))
			r.mu.Lock()
			addr := r.clientAddr
			r.mu.Unlock()
			if addr != nil {
				toSend := buf2[:n]
				if n > r.maxResponseSize {
					toSend = buf2[:r.maxResponseSize]
					if len(toSend) >= 3 {
						toSend[2] |= 0x02 // TC = 1
					}
				}
				r.ln.WriteToUDP(toSend, addr)
			}
		}
	}()
	go func() {
		for {
			n, addr, err := r.ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.clientAddr = addr
			r.mu.Unlock()
			if r.maxRequestSize > 0 {
				qnl, ok := integrationDNSQuestionQNameWireLen(buf[:n])
				if !ok || qnl > r.maxRequestSize {
					continue
				}
			}
			r.sent.Add(int64(n))
			r.serverConn.WriteToUDP(buf[:n], r.serverAddr)
		}
	}()
	return r
}

func (r *truncatingUDPRelay) Addr() string {
	if r.advertiseAddr != "" {
		return r.advertiseAddr
	}
	return r.ln.LocalAddr().String()
}

func (r *truncatingUDPRelay) Close() {
	r.ln.Close()
	r.serverConn.Close()
}

// slowLossyTruncatingUDPRelay is like truncatingUDPRelay (response truncate + query wire drop) but also
// adds one-way server→client delay (realistic slow internet) and drops every
// dropClientEvery-th client→server packet (queries that never reach the server).
// Used for integrity tests over a constrained, slow, and lossy path.
type slowLossyTruncatingUDPRelay struct {
	ln              *net.UDPConn
	serverConn      *net.UDPConn
	serverAddr      *net.UDPAddr
	advertiseAddr   string
	maxResponseSize int // DNS response wire (UDP payload)
	maxRequestSize  int // max question QNAME wire octets; 0 = no limit
	serverDelay     time.Duration
	dropClientEvery int

	sent       atomic.Int64
	received   atomic.Int64
	mu         sync.Mutex
	clientAddr *net.UDPAddr

	clientPackets atomic.Int64
}

// newSlowLossyTruncatingUDPRelay maxRequestSize = max QNAME wire octets (DPI-style).
func newSlowLossyTruncatingUDPRelay(t testing.TB, serverAddrStr string, maxResponseSize, maxRequestSize int, serverDelay time.Duration, dropClientEvery int) *slowLossyTruncatingUDPRelay {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("resolve server addr: %v", err)
	}
	listenAddr := relayListenUDPAddr(t)
	ln, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		t.Fatalf("slow-lossy relay listen: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", relayUpstreamBindAddr(listenAddr))
	if err != nil {
		ln.Close()
		t.Fatalf("slow-lossy relay server conn: %v", err)
	}
	r := &slowLossyTruncatingUDPRelay{
		ln:              ln,
		serverConn:      serverConn,
		serverAddr:      serverAddr,
		advertiseAddr:   relayAdvertiseAddr(t, ln.LocalAddr().String(), serverAddrStr),
		maxResponseSize: maxResponseSize,
		maxRequestSize:  maxRequestSize,
		serverDelay:     serverDelay,
		dropClientEvery: dropClientEvery,
	}
	go r.serverToClientLoop()
	go r.clientToServerLoop()
	return r
}

func (r *slowLossyTruncatingUDPRelay) serverToClientLoop() {
	buf := make([]byte, 4096)
	for {
		n, _, err := r.serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.received.Add(int64(n))
		r.mu.Lock()
		addr := r.clientAddr
		r.mu.Unlock()
		if addr == nil {
			continue
		}
		toSend := buf[:n]
		if n > r.maxResponseSize {
			toSend = buf[:r.maxResponseSize]
			if len(toSend) >= 3 {
				toSend[2] |= 0x02 // TC = 1
			}
		}
		send := func(p []byte) {
			payload := append([]byte(nil), p...)
			if r.serverDelay > 0 {
				time.AfterFunc(r.serverDelay, func() {
					r.ln.WriteToUDP(payload, addr)
				})
			} else {
				r.ln.WriteToUDP(payload, addr)
			}
		}
		send(toSend)
	}
}

func (r *slowLossyTruncatingUDPRelay) clientToServerLoop() {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := r.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.clientAddr = clientAddr
		r.mu.Unlock()
		if r.maxRequestSize > 0 {
			qnl, ok := integrationDNSQuestionQNameWireLen(buf[:n])
			if !ok || qnl > r.maxRequestSize {
				continue
			}
		}
		seq := int(r.clientPackets.Add(1))
		if seq > r.dropClientEvery*2 && r.dropClientEvery > 0 && seq%r.dropClientEvery == 0 {
			continue
		}
		r.sent.Add(int64(n))
		r.serverConn.WriteToUDP(buf[:n], r.serverAddr)
	}
}

func newTruncatingUDPRelayWithClientQueryWireLimit(t testing.TB, serverAddrStr string, maxDNSResponseWire, maxClientQueryWire int) *truncatingUDPRelay {
	return newTruncatingUDPRelayWithRequestLimit(t, serverAddrStr, maxDNSResponseWire, maxClientQueryWire)
}

func (r *slowLossyTruncatingUDPRelay) Addr() string {
	if r.advertiseAddr != "" {
		return r.advertiseAddr
	}
	return r.ln.LocalAddr().String()
}

func (r *slowLossyTruncatingUDPRelay) Close() {
	r.ln.Close()
	r.serverConn.Close()
}

// chaosUDPRelay injects packet loss, delay, and duplication between client and server.
// It is used to simulate realistic DNS transport faults in integration tests.
type chaosUDPRelay struct {
	ln            *net.UDPConn
	serverConn    *net.UDPConn
	serverAddr    *net.UDPAddr
	advertiseAddr string

	mu         sync.Mutex
	clientAddr *net.UDPAddr

	dropClientEvery      int
	dropServerEvery      int
	duplicateServerEvery int
	serverDelay          time.Duration

	clientPackets atomic.Int64
	serverPackets atomic.Int64
}

func newChaosUDPRelay(t testing.TB, serverAddrStr string, dropClientEvery, dropServerEvery, duplicateServerEvery int, serverDelay time.Duration) *chaosUDPRelay {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("resolve server addr: %v", err)
	}
	listenAddr := relayListenUDPAddr(t)
	ln, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		t.Fatalf("chaos relay listen: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", relayUpstreamBindAddr(listenAddr))
	if err != nil {
		ln.Close()
		t.Fatalf("chaos relay server conn: %v", err)
	}
	r := &chaosUDPRelay{
		ln:                   ln,
		serverConn:           serverConn,
		serverAddr:           serverAddr,
		advertiseAddr:        relayAdvertiseAddr(t, ln.LocalAddr().String(), serverAddrStr),
		dropClientEvery:      dropClientEvery,
		dropServerEvery:      dropServerEvery,
		duplicateServerEvery: duplicateServerEvery,
		serverDelay:          serverDelay,
	}
	go r.loop()
	return r
}

func (r *chaosUDPRelay) Addr() string {
	if r.advertiseAddr != "" {
		return r.advertiseAddr
	}
	return r.ln.LocalAddr().String()
}

func (r *chaosUDPRelay) Close() {
	r.ln.Close()
	r.serverConn.Close()
}

func (r *chaosUDPRelay) loop() {
	buf := make([]byte, 4096)
	go func() {
		buf2 := make([]byte, 4096)
		for {
			n, _, err := r.serverConn.ReadFromUDP(buf2)
			if err != nil {
				return
			}
			seq := int(r.serverPackets.Add(1))
			if r.dropServerEvery > 0 && seq%r.dropServerEvery == 0 {
				continue
			}
			r.mu.Lock()
			clientAddr := r.clientAddr
			r.mu.Unlock()
			if clientAddr == nil {
				continue
			}
			payload := append([]byte(nil), buf2[:n]...)
			send := func(p []byte) {
				if r.serverDelay > 0 {
					time.AfterFunc(r.serverDelay, func() {
						r.ln.WriteToUDP(p, clientAddr)
					})
				} else {
					r.ln.WriteToUDP(p, clientAddr)
				}
			}
			send(payload)
			if r.duplicateServerEvery > 0 && seq%r.duplicateServerEvery == 0 {
				dup := append([]byte(nil), payload...)
				send(dup)
			}
		}
	}()
	for {
		n, clientAddr, err := r.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		seq := int(r.clientPackets.Add(1))
		r.mu.Lock()
		r.clientAddr = clientAddr
		r.mu.Unlock()
		if r.dropClientEvery > 0 && seq%r.dropClientEvery == 0 {
			continue
		}
		r.serverConn.WriteToUDP(buf[:n], r.serverAddr)
	}
}

// truncatingEveryNthUDPRelay truncates every Nth server->client response to
// simulate malformed DNS packets in transit.
type truncatingEveryNthUDPRelay struct {
	ln            *net.UDPConn
	serverConn    *net.UDPConn
	serverAddr    *net.UDPAddr
	advertiseAddr string
	truncateEvery int
	truncateTo    int

	mu         sync.Mutex
	clientAddr *net.UDPAddr

	serverPackets atomic.Int64
}

func newTruncatingEveryNthUDPRelay(t testing.TB, serverAddrStr string, truncateEvery, truncateTo int) *truncatingEveryNthUDPRelay {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("resolve server addr: %v", err)
	}
	listenAddr := relayListenUDPAddr(t)
	ln, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		t.Fatalf("truncating-nth relay listen: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", relayUpstreamBindAddr(listenAddr))
	if err != nil {
		ln.Close()
		t.Fatalf("truncating-nth relay server conn: %v", err)
	}
	r := &truncatingEveryNthUDPRelay{
		ln:            ln,
		serverConn:    serverConn,
		serverAddr:    serverAddr,
		advertiseAddr: relayAdvertiseAddr(t, ln.LocalAddr().String(), serverAddrStr),
		truncateEvery: truncateEvery,
		truncateTo:    truncateTo,
	}
	go r.loop()
	return r
}

func (r *truncatingEveryNthUDPRelay) Addr() string {
	if r.advertiseAddr != "" {
		return r.advertiseAddr
	}
	return r.ln.LocalAddr().String()
}

func (r *truncatingEveryNthUDPRelay) Close() {
	r.ln.Close()
	r.serverConn.Close()
}

func (r *truncatingEveryNthUDPRelay) loop() {
	buf := make([]byte, 4096)
	go func() {
		buf2 := make([]byte, 4096)
		for {
			n, _, err := r.serverConn.ReadFromUDP(buf2)
			if err != nil {
				return
			}
			seq := int(r.serverPackets.Add(1))
			r.mu.Lock()
			clientAddr := r.clientAddr
			r.mu.Unlock()
			if clientAddr == nil {
				continue
			}
			toSend := buf2[:n]
			if r.truncateEvery > 0 && seq%r.truncateEvery == 0 && r.truncateTo > 0 && r.truncateTo < len(toSend) {
				toSend = buf2[:r.truncateTo]
			}
			r.ln.WriteToUDP(toSend, clientAddr)
		}
	}()
	for {
		n, clientAddr, err := r.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.clientAddr = clientAddr
		r.mu.Unlock()
		r.serverConn.WriteToUDP(buf[:n], r.serverAddr)
	}
}

const (
	ednsOptionUpstream   = 0xFF00 // client → server payload
	ednsOptionDownstream = 0xFF01 // server → client payload
)

// logDNSMessage parses wire as DNS and logs a short summary via tb.Logf.
// For tunnel messages, also logs tunnel payload length (EDNS option 0xFF00/0xFF01)
// so the log shows that real application data is carried inside DNS.
func logDNSMessage(tb testing.TB, direction string, wire []byte) {
	msg, err := dns.MessageFromWireFormat(wire)
	if err != nil {
		tb.Logf("DNS %s: [parse error: %v] %d bytes", direction, err, len(wire))
		return
	}
	// Tunnel payload size from OPT RR (proves data is in the message).
	var payloadLen int
	for _, rr := range msg.Additional {
		if rr.Type == dns.RRTypeOPT && len(rr.Data) > 0 {
			opts, err := dns.ParseEDNSOptions(rr.Data)
			if err != nil {
				continue
			}
			if (msg.Flags & 0x8000) == 0 {
				if p := dns.FindEDNSOption(opts, ednsOptionUpstream); p != nil {
					payloadLen = len(p)
					break
				}
			} else {
				if p := dns.FindEDNSOption(opts, ednsOptionDownstream); p != nil {
					payloadLen = len(p)
					break
				}
			}
		}
	}

	qr := "query"
	if (msg.Flags & 0x8000) != 0 {
		qr = "response"
	}
	if qr == "query" {
		var qs []string
		for _, q := range msg.Question {
			qs = append(qs, fmt.Sprintf("%s type=%d", q.Name.String(), q.Type))
		}
		if len(qs) == 0 {
			qs = append(qs, "(no question)")
		}
		if payloadLen > 0 {
			tb.Logf("DNS %s: id=%d %s → %s tunnel_payload=%d bytes", direction, msg.ID, qr, qs, payloadLen)
		} else {
			tb.Logf("DNS %s: id=%d %s → %s", direction, msg.ID, qr, qs)
		}
	} else {
		rcode := msg.Rcode()
		rcodeStr := map[uint16]string{
			0: "NOERROR", 1: "FORMERR", 3: "NXDOMAIN", 4: "NOTIMPL",
		}
		s := rcodeStr[rcode]
		if s == "" {
			s = fmt.Sprintf("RCODE%d", rcode)
		}
		if payloadLen > 0 {
			tb.Logf("DNS %s: id=%d %s rcode=%s ancount=%d tunnel_payload=%d bytes", direction, msg.ID, qr, s, len(msg.Answer), payloadLen)
		} else {
			tb.Logf("DNS %s: id=%d %s rcode=%s ancount=%d", direction, msg.ID, qr, s, len(msg.Answer))
		}
	}
}
