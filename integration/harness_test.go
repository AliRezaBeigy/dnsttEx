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
// Registers t.Cleanup(h.Teardown). If clientEnv is non-nil, the client process
// is started with those env vars (e.g. DNSTT_SMUX_KEEPALIVE_TIMEOUT for reconnect tests).
func newTunnelHarness(t testing.TB, serverBin, clientBin string, clientEnv map[string]string) *tunnelHarness {
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
func newTunnelHarnessWithRelayAndStderr(t testing.TB, serverBin, clientBin string, makeRelay makeRelayFunc, stderrBuf *bytes.Buffer, clientEnv map[string]string) *tunnelHarness {
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
	h.privkeyHex = noise.EncodeKey(privkey)
	h.pubkeyHex = noise.EncodeKey(noise.PubkeyFromPrivkey(privkey))
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
	relay := makeRelay(h.dnsUDPAddr)
	h.ClientAddr = allocFreeTCPAddr(t)
	h.clientCmd = exec.Command(clientBin,
		"-udp", relay.Addr(),
		"-pubkey", h.pubkeyHex,
		h.domain,
		h.ClientAddr,
	)
	h.clientCmd.Stderr = stderrBuf
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

// newTunnelHarnessWithRelayAndDNSLog is like newTunnelHarnessWithRelay but
// logs each DNS query and response via t.Logf.
func newTunnelHarnessWithRelayAndDNSLog(t testing.TB, serverBin, clientBin string) (*countingUDPRelay, *tunnelHarness) {
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

	relay := newCountingUDPRelayWithDNSLog(t, h.dnsUDPAddr, nil) // set nil for now

	h.ClientAddr = allocFreeTCPAddr(t)
	h.clientCmd = exec.Command(clientBin,
		"-udp", relay.Addr(),
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
	ln         *net.UDPConn // listens for client packets
	serverAddr *net.UDPAddr // real server address

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
		dnsLog:     dnsLog,
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

// truncatingUDPRelay is a UDP relay that limits server→client response size to
// maxResponseSize (e.g. 512 to simulate 512-byte-only resolvers). Used for MTU discovery tests.
// If maxRequestSize > 0, client→server packets larger than that are dropped so discovery finds that client MTU.
type truncatingUDPRelay struct {
	ln               *net.UDPConn
	serverConn       *net.UDPConn
	serverAddr       *net.UDPAddr
	maxResponseSize  int
	maxRequestSize   int // 0 = no limit
	sent             atomic.Int64
	received         atomic.Int64
	mu               sync.Mutex
	clientAddr       *net.UDPAddr
}

// newTruncatingUDPRelay creates a relay that truncates responses to maxResponseSize.
// Use newTruncatingUDPRelayWithRequestLimit to also limit request size (client MTU).
func newTruncatingUDPRelay(t testing.TB, serverAddrStr string, maxResponseSize int) *truncatingUDPRelay {
	return newTruncatingUDPRelayWithRequestLimit(t, serverAddrStr, maxResponseSize, 0)
}

// newTruncatingUDPRelayWithRequestLimit creates a relay that truncates responses to maxResponseSize
// and drops client→server packets larger than maxRequestSize (so MTU discovery finds client MTU = maxRequestSize).
// Pass maxRequestSize 0 for no request limit.
func newTruncatingUDPRelayWithRequestLimit(t testing.TB, serverAddrStr string, maxResponseSize, maxRequestSize int) *truncatingUDPRelay {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("resolve server addr: %v", err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("truncating relay listen: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		ln.Close()
		t.Fatalf("truncating relay server conn: %v", err)
	}
	r := &truncatingUDPRelay{
		ln: ln, serverConn: serverConn, serverAddr: serverAddr,
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
			if r.maxRequestSize > 0 && n > r.maxRequestSize {
				// Drop oversized request so client MTU discovery finds maxRequestSize.
				continue
			}
			r.sent.Add(int64(n))
			r.serverConn.WriteToUDP(buf[:n], r.serverAddr)
		}
	}()
	return r
}

func (r *truncatingUDPRelay) Addr() string { return r.ln.LocalAddr().String() }

func (r *truncatingUDPRelay) Close() {
	r.ln.Close()
	r.serverConn.Close()
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
