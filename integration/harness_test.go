//go:build integration

package integration_test

import (
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

	"dnsttEx/noise"
)

var (
	globalServerBin string
	globalClientBin string
)

func TestMain(m *testing.M) {
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
		{filepath.Join(dir, "dnstt-server"+ext), filepath.Join(root, "dnstt-server")},
		{filepath.Join(dir, "dnstt-client"+ext), filepath.Join(root, "dnstt-client")},
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

// newTunnelHarness starts a full tunnel stack and waits for it to be ready.
// Registers t.Cleanup(h.Teardown).
func newTunnelHarness(t testing.TB, serverBin, clientBin string) *tunnelHarness {
	t.Helper()

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

	// 3. Free UDP port for DNS server.
	h.dnsUDPAddr = allocFreeUDPAddr(t)

	// 4. Start dnstt-server.
	h.serverCmd = exec.Command(serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		h.domain,
		echoLn.Addr().String(),
	)
	h.serverCmd.Stderr = os.Stderr
	if err := h.serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	// Give server time to bind its UDP socket.
	time.Sleep(300 * time.Millisecond)

	// 5. Free TCP port for client listener.
	h.ClientAddr = allocFreeTCPAddr(t)

	// 6. Start dnstt-client.
	h.clientCmd = exec.Command(clientBin,
		"-udp", h.dnsUDPAddr,
		"-pubkey", h.pubkeyHex,
		h.domain,
		h.ClientAddr,
	)
	h.clientCmd.Stderr = os.Stderr
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

	h.dnsUDPAddr = allocFreeUDPAddr(t)

	h.serverCmd = exec.Command(serverBin,
		"-udp", h.dnsUDPAddr,
		"-privkey", h.privkeyHex,
		h.domain,
		echoLn.Addr().String(),
	)
	h.serverCmd.Stderr = os.Stderr
	if err := h.serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Insert counting relay between client and server.
	relay := newCountingUDPRelay(t, h.dnsUDPAddr)

	h.ClientAddr = allocFreeTCPAddr(t)
	h.clientCmd = exec.Command(clientBin,
		"-udp", relay.Addr(), // client → relay → server
		"-pubkey", h.pubkeyHex,
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

// pingPong sends one byte and reads one byte back (15s deadline).
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
}

// TestSanity verifies the harness works: starts the full stack and does a 1-byte echo.
func TestSanity(t *testing.T) {
	h := newTunnelHarness(t, globalServerBin, globalClientBin)
	conn := h.dialTunnel(t)
	defer conn.Close()
	pingPong(t, conn, "sanity")
	t.Log("sanity echo OK")
}

// --- countingUDPRelay ---

// countingUDPRelay is a transparent UDP middleman between client and server.
// It counts raw bytes in both directions for wire-overhead measurement.
type countingUDPRelay struct {
	ln         *net.UDPConn // listens for client packets
	serverAddr *net.UDPAddr // real server address

	sent     atomic.Int64 // bytes forwarded client → server
	received atomic.Int64 // bytes forwarded server → client

	mu         sync.Mutex
	clientAddr *net.UDPAddr // last known client address (filled on first packet)

	done chan struct{}
}

func newCountingUDPRelay(t testing.TB, serverAddrStr string) *countingUDPRelay {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("resolve server addr: %v", err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	r := &countingUDPRelay{
		ln:         ln,
		serverAddr: serverAddr,
		done:       make(chan struct{}),
	}
	go r.loop()
	return r
}

// Addr returns the UDP address clients should send queries to.
func (r *countingUDPRelay) Addr() string {
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
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
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
		r.sent.Add(int64(n))
		r.mu.Lock()
		r.clientAddr = clientAddr
		r.mu.Unlock()
		serverConn.WriteToUDP(buf[:n], r.serverAddr)
	}
}
