// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client [-doh URL|-dot ADDR|-udp ADDR] (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN LOCALADDR
//
// Examples:
//
//	dnstt-client -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-udp resolver.example:53
//
// Flags may be repeated to specify multiple resolvers:
//
//	-doh url1 -doh url2 -dot addr1 -udp addr2
//
// A resolver file may also be given:
//
//	-resolvers-file /path/to/resolvers.txt
//
// File format: one resolver per line, prefix doh:, dot:, or udp:.
// Lines starting with # or blank lines are ignored.
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// LOCALADDR is the TCP address that will listen for connections and forward
// them over the tunnel.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dnsttEx/dns"
	"dnsttEx/internal/kcp"
	"dnsttEx/noise"
	"dnsttEx/turbotunnel"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

// smux streams will be closed after this much time without receiving data.
const (
	idleTimeout = 2 * time.Minute
	// mtuProbeNXDOMAINRetries: when request-size MTU probe gets NXDOMAIN, retry this many times before giving up.
	mtuProbeNXDOMAINRetries = 3
	// mtuProbeErrorRetries: when an MTU probe times out or hits a transient read/write
	// error, retry it this many times before treating that size as failed.
	mtuProbeErrorRetries = 2
	// minKCPMTU is the minimum MTU KCP accepts (IKCP_OVERHEAD+1 = 13).
	// Low-MTU DNS paths (e.g. 128-byte requests) need MTU as low as ~42
	// so each KCP segment fits inside one DNS query.
	minKCPMTU = 13
)

// dnsttDebug returns true when DNSTT_DEBUG is set (for verbose PING/PONG and MTU discovery logs).
func dnsttDebug() bool { return os.Getenv("DNSTT_DEBUG") != "" }

// dnsttLogRxData enables DNS payload tracing: RX (answers) and TX (data sends only; idle polls not logged).
// Set DNSTT_LOG_RX_DATA=1. Lines: DNSTT_TX_DATA → (tunnel upstream), DNSTT_RX_* ← (downstream).
func dnsttLogRxData() bool { return os.Getenv("DNSTT_LOG_RX_DATA") != "" }

// dnsttTrace returns true when DNSTT_TRACE is set (for full path tracing to diagnose failures).
func dnsttTrace() bool { return os.Getenv("DNSTT_TRACE") != "" }

// mtuProbeTimeout returns the per-probe timeout for MTU discovery. Default 8s.
// Set DNSTT_MTU_PROBE_TIMEOUT to a duration (e.g. "2s", "1500ms") to use a shorter timeout
// (e.g. in integration tests where dropped probes would otherwise block 8s).
func mtuProbeTimeout() time.Duration {
	s := os.Getenv("DNSTT_MTU_PROBE_TIMEOUT")
	if s == "" {
		return 8 * time.Second
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 8 * time.Second
	}
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	return d
}

// dnsttDebugHexDump returns a hex dump of b for DNSTT_DEBUG logs. If len(b) > max, only the first max bytes are shown.
func dnsttDebugHexDump(b []byte, max int) string {
	const defaultMax = 512
	if max <= 0 {
		max = defaultMax
	}
	if len(b) <= max {
		return hex.Dump(b)
	}
	return hex.Dump(b[:max]) + fmt.Sprintf("\t... (%d bytes total)\n", len(b))
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

// sessionManager manages the KCP connection, Noise channel, and smux session,
// and can recreate them if they become closed.
type sessionManager struct {
	pubkey     []byte
	domain     dns.Name
	remoteAddr net.Addr
	pconn      net.PacketConn
	mtu        int

	mu       sync.RWMutex
	createMu sync.Mutex // serializes createSession so only one full handshake runs
	conn     *kcp.UDPSession
	rw       io.ReadWriteCloser
	sess     *smux.Session
	conv     uint32
}

// newSessionManager creates a new session manager.
func newSessionManager(pubkey []byte, domain dns.Name, remoteAddr net.Addr, pconn net.PacketConn, mtu int) *sessionManager {
	return &sessionManager{
		pubkey:     pubkey,
		domain:     domain,
		remoteAddr: remoteAddr,
		pconn:      pconn,
		mtu:        mtu,
	}
}

// closeSessionLocked closes the current session if it exists.
// Caller must hold sm.mu write lock.
func (sm *sessionManager) closeSessionLocked() {
	if sm.sess != nil {
		sm.sess.Close()
		sm.sess = nil
	}
	if sm.rw != nil {
		sm.rw.Close()
		sm.rw = nil
	}
	if sm.conn != nil {
		conv := sm.conv
		log.Printf("end session %08x", conv)
		sm.conn.Close()
		sm.conn = nil
	}
	sm.conv = 0
}

// createSessionUnlocked creates a new KCP connection, Noise channel, and smux
// session. It does not touch sm.mu and must be called without holding it.
func (sm *sessionManager) createSessionUnlocked() (*kcp.UDPSession, io.ReadWriteCloser, *smux.Session, uint32, error) {
	conn, err := kcp.NewConn2(sm.remoteAddr, nil, 0, 0, sm.pconn)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("opening KCP conn: %v", err)
	}
	conv := conn.GetConv()
	log.Printf("begin session %08x", conv)

	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows). Use nodelay=1 and resend=2 for
	// fast retransmit on the high-latency, potentially lossy DNS transport.
	conn.SetNoDelay(
		1,  // nodelay=1: flush immediately, no Nagle-like coalescing delay
		20, // interval=20ms: KCP update tick (0 causes edge-case behavior in kcp-go)
		2,  // resend=2: fast retransmit after 2 ACK gaps (0 = disabled)
		1,  // nc=1: congestion window off
	)
	// DNS can take many seconds to respond; set minimum RTO so we don't retransmit too soon and burst.
	kcpMinRTO := uint32(1000)
	if s := os.Getenv("DNSTT_KCP_MIN_RTO_MS"); s != "" {
		if ms, err := strconv.ParseUint(s, 10, 32); err == nil {
			kcpMinRTO = uint32(ms)
		}
	}
	conn.SetMinRTO(kcpMinRTO)
	conn.SetWindowSize(512, 512) // was QueueSize/2=64; larger window for high-latency DNS
	if !conn.SetMtu(sm.mtu) {
		conn.Close()
		return nil, nil, nil, 0, fmt.Errorf("KCP SetMtu(%d) failed (minimum %d)", sm.mtu, minKCPMTU)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, sm.pubkey)
	if err != nil {
		conn.Close()
		return nil, nil, nil, 0, err
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = 10 * time.Second
	smuxConfig.KeepAliveTimeout = 30 * time.Second
	if s := os.Getenv("DNSTT_SMUX_KEEPALIVE_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d >= time.Second {
			smuxConfig.KeepAliveInterval = d
		}
	}
	if s := os.Getenv("DNSTT_SMUX_KEEPALIVE_TIMEOUT"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d >= time.Second {
			smuxConfig.KeepAliveTimeout = d
		}
	}
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		rw.Close()
		conn.Close()
		return nil, nil, nil, 0, fmt.Errorf("opening smux session: %v", err)
	}

	return conn, rw, sess, conv, nil
}

// createSession closes any existing session and establishes a new one.
// Caller must NOT hold sm.mu. createMu ensures only one goroutine runs the
// full handshake (createSessionUnlocked); concurrent callers block and then
// use the same session instead of creating duplicates that get discarded.
func (sm *sessionManager) createSession() error {
	sm.createMu.Lock()
	defer sm.createMu.Unlock()

	sm.mu.Lock()
	if sm.sess != nil {
		sm.mu.Unlock()
		return nil
	}
	sm.closeSessionLocked()
	sm.mu.Unlock()

	conn, rw, sess, conv, err := sm.createSessionUnlocked()
	if err != nil {
		return err
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.sess != nil {
		sess.Close()
		rw.Close()
		conn.Close()
		log.Printf("discarding duplicate session %08x (already have %08x)", conv, sm.conv)
		return nil
	}
	sm.conn = conn
	sm.rw = rw
	sm.sess = sess
	sm.conv = conv
	return nil
}

// closeSession closes the current session if it exists.
func (sm *sessionManager) closeSession() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.closeSessionLocked()
}

// getSession returns the current session, creating one if needed.
// Must not hold sm.mu when calling this function.
func (sm *sessionManager) getSession() (*smux.Session, uint32, error) {
	// Fast path: session already exists.
	sm.mu.RLock()
	sess, conv := sm.sess, sm.conv
	sm.mu.RUnlock()
	if sess != nil {
		return sess, conv, nil
	}

	// Slow path: createSession manages its own locking; must not hold sm.mu.
	if err := sm.createSession(); err != nil {
		return nil, 0, err
	}
	sm.mu.RLock()
	sess, conv = sm.sess, sm.conv
	sm.mu.RUnlock()
	return sess, conv, nil
}

// openStream opens a new stream, recreating the session if it appears closed.
func (sm *sessionManager) openStream() (*smux.Stream, uint32, error) {
	sess, conv, err := sm.getSession()
	if err != nil {
		return nil, 0, err
	}

	stream, err := sess.OpenStream()
	if err == nil {
		return stream, conv, nil
	}

	errStr := err.Error()
	isClosedError := errors.Is(err, io.ErrClosedPipe) ||
		strings.Contains(errStr, "closed pipe") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "use of closed network connection") ||
		err == io.EOF

	if !isClosedError {
		return nil, 0, fmt.Errorf("session %08x opening stream: %v", conv, err)
	}

	log.Printf("session %08x closed, recreating: %v", conv, err)
	// Clear the dead session only if it hasn't already been replaced by
	// another goroutine.
	sm.mu.Lock()
	if sm.sess == sess {
		sm.closeSessionLocked()
	}
	sm.mu.Unlock()

	// Delegate to getSession which will call createSession if needed.
	sess, conv, err = sm.getSession()
	if err != nil {
		return nil, 0, fmt.Errorf("recreating session: %v", err)
	}
	stream, err = sess.OpenStream()
	if err != nil {
		return nil, 0, fmt.Errorf("session %08x opening stream after recreate: %v", conv, err)
	}
	return stream, conv, nil
}

func handle(local *net.TCPConn, sm *sessionManager) error {
	stream, conv, err := sm.openStream()
	if err != nil {
		return fmt.Errorf("opening stream: %v", err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

// packetConnWithDone is implemented by PacketConns that signal when they are closed
// (e.g. turbotunnel.QueuePacketConn and DNSPacketConn). run() uses it to exit when
// the tunnel transport is closed.
type packetConnWithDone interface {
	net.PacketConn
	Done() <-chan struct{}
}

type kcpMTUHint interface {
	KCPMTUHint() int
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	// KCP segment must fit in one DNS name: decoded = clientID(8) + paddingByte(1) + padding(numPadding) + length(1) + payload.
	capacity := nameCapacity(domain)
	overhead := 8 + 1 + numPadding + 1
	maxPayloadInName := capacity - overhead
	if maxPayloadInName < 1 {
		return fmt.Errorf("domain %s leaves no room for payload (capacity %d)", domain, capacity)
	}
	mtu := maxPacketSize
	if maxPayloadInName < mtu {
		mtu = maxPayloadInName
	}
	if hintConn, ok := pconn.(kcpMTUHint); ok {
		if hint := hintConn.KCPMTUHint(); hint >= minKCPMTU && hint < mtu {
			mtu = hint
		} else if hint > 0 && hint < minKCPMTU && dnsttTrace() {
			log.Printf("DNSTT_TRACE: client run: ignoring request-path MTU hint %d below KCP minimum %d", hint, minKCPMTU)
		}
	}
	if mtu < minKCPMTU {
		return fmt.Errorf("tunnel MTU %d bytes is below KCP minimum (%d); use a shorter domain or larger path MTU", mtu, minKCPMTU)
	}
	log.Printf("Tunnel MTU: %d bytes", mtu)

	// Create session manager. Session (KCP + Noise + smux) is created lazily on
	// first TCP connection via getSession(), so no handshake burst when no app is connected.
	sm := newSessionManager(pubkey, domain, remoteAddr, pconn, mtu)
	defer sm.closeSession()

	if dpc, ok := pconn.(packetConnWithDone); ok {
		// When pconn is closed (e.g. dnsConn.Close() in tests), exit so run() returns.
		acceptCh := make(chan net.Conn, 1)
		go func() {
			for {
				local, err := ln.Accept()
				if err != nil {
					close(acceptCh)
					return
				}
				select {
				case acceptCh <- local:
				case <-dpc.Done():
					local.Close()
					close(acceptCh)
					return
				}
			}
		}()
		for {
			select {
			case <-dpc.Done():
				return nil
			case local, ok := <-acceptCh:
				if !ok {
					return nil
				}
				go func(c net.Conn) {
					defer c.Close()
					if err := handle(c.(*net.TCPConn), sm); err != nil {
						log.Printf("handle: %v", err)
					}
				}(local)
			}
		}
	}

	for {
		local, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sm)
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

var dialerControl func(network, address string, c syscall.RawConn) error = nil

// stringSliceFlag is a flag.Value that collects repeated string flags into a slice.
type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// parseResolversFile parses a resolvers file and appends to specs.
// Format: one resolver per line, prefix doh:, dot:, or udp:. A bare IP or
// hostname with no prefix is treated as udp:host:53.
// Lines starting with # and blank lines are ignored.
func parseResolversFile(path string) ([]resolverSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var specs []resolverSpec
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		var typ, addr string
		if idx < 0 {
			// Bare IP or hostname: treat as UDP on port 53
			typ = "udp"
			addr = line + ":53"
		} else {
			typ = strings.ToLower(line[:idx])
			addr = line[idx+1:]
		}
		switch typ {
		case "doh", "dot", "udp":
		default:
			return nil, fmt.Errorf("resolver file: unknown type %q in line %q", typ, line)
		}
		// For doh entries that don't start with https:// add the scheme.
		if typ == "doh" && !strings.HasPrefix(strings.ToLower(addr), "https://") {
			addr = "https://" + addr + "/dns-query"
		}
		specs = append(specs, resolverSpec{typ: typ, addr: addr})
	}
	return specs, scanner.Err()
}

// scanResolvers probes each endpoint and returns only those that get a valid
// server response within timeout. If checks > 1, each UDP endpoint is probed
// checks times and passes only if all checks succeed (DoH/DoT are still
// assumed OK and pass without probing).
//
// For UDP endpoints the dedicated probeConn is used so the scan socket is
// never shared with the later readLoop. For DoH/DoT endpoints SetReadDeadline
// is a no-op on the underlying QueuePacketConn, so we log a warning and treat
// those endpoints as passing without a real probe.
func scanResolvers(endpoints []*poolEndpoint, domain dns.Name, timeout time.Duration, checks int) []*poolEndpoint {
	if checks < 1 {
		checks = 1
	}
	probeID := turbotunnel.NewClientID()
	probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
	probeVerify := func(buf []byte) bool { return VerifyProbeResponse(buf, domain) }

	var mu sync.Mutex
	var passed []*poolEndpoint
	var wg sync.WaitGroup

	for _, ep := range endpoints {
		ep := ep
		wg.Add(1)
		go func() {
			defer wg.Done()

			// DoH/DoT: no dedicated probe socket; deadlines are no-ops on
			// QueuePacketConn. Warn and pass through unconditionally.
			if ep.probeConn == nil {
				log.Printf("Scan: %s (DoH/DoT) cannot probe; assumed OK", ep.name)
				mu.Lock()
				passed = append(passed, ep)
				mu.Unlock()
				return
			}

			// UDP: run up to checks PING/PONG rounds; pass only if all succeed.
			for round := 0; round < checks; round++ {
				msg, err := probeBuilder()
				if err != nil {
					log.Printf("Scan: %s — PING build failed (check %d/%d): %v", ep.name, round+1, checks, err)
					return
				}
				ep.probeConn.SetDeadline(time.Now().Add(timeout))
				_, err = ep.probeConn.WriteTo(msg, ep.addr)
				if err != nil {
					ep.probeConn.SetDeadline(time.Time{})
					log.Printf("Scan: %s — PING send failed (check %d/%d): %v", ep.name, round+1, checks, err)
					return
				}
				if checks == 1 {
					log.Printf("Scan: %s ← PING sent", ep.name)
				} else {
					log.Printf("Scan: %s ← PING sent (check %d/%d)", ep.name, round+1, checks)
				}
				if dnsttDebug() {
					log.Printf("DNSTT_DEBUG: PING to %s (health probe, no requested payload size)", ep.name)
					log.Printf("DNSTT_DEBUG: PING query (hex):\n%s", dnsttDebugHexDump(msg, 0))
				}
				buf := make([]byte, 4096)
				n, _, err := ep.probeConn.ReadFrom(buf)
				ep.probeConn.SetDeadline(time.Time{})
				if err != nil {
					log.Printf("Scan: %s — no PONG (check %d/%d: %v)", ep.name, round+1, checks, err)
					return
				}
				if dnsttDebug() {
					log.Printf("DNSTT_DEBUG: PONG response (hex):\n%s", dnsttDebugHexDump(buf[:n], 0))
				}
				if !probeVerify(buf[:n]) {
					log.Printf("Scan: %s → bad response (check %d/%d): %s", ep.name, round+1, checks, ExplainProbeResponseFailure(buf[:n], domain))
					return
				}
				payloadLen := 0
				if resp, err := dns.MessageFromWireFormat(buf[:n]); err == nil {
					payload := dnsResponsePayload(&resp, domain)
					payloadLen = len(payload)
				}
				if checks == 1 {
					log.Printf("Scan: %s → PONG received (%d bytes)", ep.name, payloadLen)
				} else {
					log.Printf("Scan: %s → PONG received (check %d/%d, %d bytes)", ep.name, round+1, checks, payloadLen)
				}
				if dnsttDebug() {
					log.Printf("DNSTT_DEBUG: PONG from %s payload %d bytes (health probe)", ep.name, payloadLen)
				}
			}
			mu.Lock()
			passed = append(passed, ep)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return passed
}

// mtuProbe represents a single MTU probe (server response size or client request size).
type mtuProbe struct {
	msg          []byte
	expectedName string
	size         int
	isServer     bool // true = server/response MTU, false = client/request MTU
	succeeded    bool
	skipRetry    bool // set when sizes above max-successful shouldn't be retried
}

func (p *mtuProbe) done() bool { return p.succeeded || p.skipRetry }

// discoverMTU finds max DNS response wire (server MTU) and max question QNAME length (client MTU)
// that work for this resolver. All probe sizes (both directions) are sent concurrently
// in each round, with up to 2 retry rounds for probes that don't get a response.
// If clientMTUOverride > 0, client request size is not probed and that value is used.
func discoverMTU(ep *poolEndpoint, domain dns.Name, timeout time.Duration, clientMTUOverride int) {
	if ep.probeConn == nil {
		return
	}
	probeID := turbotunnel.NewClientID()

	serverSizes := []int{256, 384, 512, 1024, 1232, 1452, 2048, 4096}
	// Client path: DPI-style limit on question QNAME wire length (not UDP payload).
	clientSizes := []int{32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 255}
	if clientMTUOverride > 0 {
		clientSizes = nil // user set -mtu: skip client request size probes
	}

	probes := make([]*mtuProbe, 0, len(serverSizes)+len(clientSizes))
	nameToProbe := make(map[string]*mtuProbe, len(serverSizes)+len(clientSizes))

	for _, size := range serverSizes {
		msg, err := BuildMTUProbeMessage(domain, probeID, size)
		if err != nil {
			continue
		}
		var name string
		if q, e := dns.MessageFromWireFormat(msg); e == nil && len(q.Question) == 1 {
			name = q.Question[0].Name.String()
		}
		p := &mtuProbe{msg: msg, expectedName: name, size: size, isServer: true}
		probes = append(probes, p)
		if name != "" {
			nameToProbe[name] = p
		}
	}
	for _, size := range clientSizes {
		msg, err := BuildProbeMessageWithRequestSize(domain, probeID, size)
		if err != nil {
			continue
		}
		var name string
		if q, e := dns.MessageFromWireFormat(msg); e == nil && len(q.Question) == 1 {
			name = q.Question[0].Name.String()
		}
		p := &mtuProbe{msg: msg, expectedName: name, size: size, isServer: false}
		probes = append(probes, p)
		if name != "" {
			nameToProbe[name] = p
		}
	}

	if dnsttDebug() {
		log.Printf("DNSTT_DEBUG: MTU discovery %s: %d probes (%d server + %d client), sending concurrently",
			ep.name, len(probes), len(serverSizes), len(clientSizes))
	}

	const maxRounds = 2
	for round := 0; round < maxRounds; round++ {
		pending := 0
		for _, p := range probes {
			if !p.done() {
				pending++
			}
		}
		if pending == 0 {
			break
		}
		if dnsttDebug() && round > 0 {
			log.Printf("DNSTT_DEBUG: MTU discovery %s: round %d, retrying %d unanswered probes",
				ep.name, round+1, pending)
		}

		sent := 0
		for _, p := range probes {
			if p.done() {
				continue
			}
			if _, err := ep.probeConn.WriteTo(p.msg, ep.addr); err != nil {
				if dnsttDebug() {
					kind := "response"
					if !p.isServer {
						kind = "request"
					}
					log.Printf("DNSTT_DEBUG: MTU probe %s: round %d write error (%s size %d): %v",
						ep.name, round+1, kind, p.size, err)
				}
				continue
			}
			sent++
		}

		deadline := time.Now().Add(timeout)
		ep.probeConn.SetDeadline(deadline)
		received := 0
		for {
			buf := make([]byte, 4096)
			n, _, err := ep.probeConn.ReadFrom(buf)
			if err != nil {
				break
			}
			received++
			resp, parseErr := dns.MessageFromWireFormat(buf[:n])
			if parseErr != nil || len(resp.Question) != 1 {
				if received >= sent {
					break
				}
				continue
			}
			p, found := nameToProbe[resp.Question[0].Name.String()]
			if !found || p.done() {
				if received >= sent {
					break
				}
				continue
			}

			ok := false
			if p.isServer {
				ok = VerifyMTUProbeResponse(buf[:n], domain, p.size)
			} else {
				ok = VerifyProbeResponse(buf[:n], domain)
			}
			if ok {
				p.succeeded = true
			} else {
				p.skipRetry = true
			}
			if dnsttDebug() {
				kind := "response"
				if !p.isServer {
					kind = "request"
				}
				if ok {
					log.Printf("DNSTT_DEBUG: MTU probe %s: %s size %d OK (round %d)",
						ep.name, kind, p.size, round+1)
				} else {
					log.Printf("DNSTT_DEBUG: MTU probe %s: %s size %d verification failed (round %d)",
						ep.name, kind, p.size, round+1)
				}
			}

			allDone := true
			for _, p := range probes {
				if !p.done() {
					allDone = false
					break
				}
			}
			if allDone || received >= sent {
				break
			}
		}
		ep.probeConn.SetDeadline(time.Time{})

		// MTU behavior is monotonic: if size S succeeds and S+1 doesn't, all sizes
		// above S will also fail (truncated by the path). Skip retrying those probes
		// so we don't burn full timeout rounds on sizes we already know won't work.
		// Only retry probes below maxSuccess that might have been lost to network jitter.
		maxServerOK, maxClientOK := 0, 0
		for _, p := range probes {
			if !p.succeeded {
				continue
			}
			if p.isServer && p.size > maxServerOK {
				maxServerOK = p.size
			}
			if !p.isServer && p.size > maxClientOK {
				maxClientOK = p.size
			}
		}
		for _, p := range probes {
			if p.done() {
				continue
			}
			if p.isServer && maxServerOK > 0 && p.size > maxServerOK {
				p.skipRetry = true
			}
			if !p.isServer && maxClientOK > 0 && p.size > maxClientOK {
				p.skipRetry = true
			}
		}
	}

	serverMTU := 0
	clientMTU := 0
	for _, p := range probes {
		if !p.succeeded {
			continue
		}
		if p.isServer && p.size > serverMTU {
			serverMTU = p.size
		}
		if !p.isServer && p.size > clientMTU {
			clientMTU = p.size
		}
	}
	if clientMTUOverride > 0 {
		clientMTU = clientMTUOverride
	}

	ep.setMaxSizes(serverMTU, clientMTU)
	log.Printf("MTU discovery: %s → max response wire %d bytes, max query QNAME %d bytes", ep.name, serverMTU, clientMTU)
}

func main() {
	// If no command-line arguments are given, try to read options from
	// environment variables, for compatibility with shadowsocks plugins.
	// ss-local -s 0.0.0.1 -p 1 -l 1080 -k password --plugin dnstt-client --plugin-opts 'doh=https://doh.example/dns-query;domain=<domain>;pubkey=<pubkey>'
	if len(os.Args) == 1 {
		pluginOpts := os.Getenv("SS_PLUGIN_OPTIONS")
		if pluginOpts != "" {
			var dohURLs, dotAddrs, udpAddrs []string
			var resolverFiles []string
			var pubkey, domainStr, policy string

			options := strings.Split(pluginOpts, ";")
			for _, opt := range options {
				parts := strings.SplitN(opt, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				switch key {
				case "doh":
					if !strings.HasPrefix(strings.ToLower(value), "https://") {
						value = "https://" + value + "/dns-query"
					}
					dohURLs = append(dohURLs, value)
				case "dot":
					dotAddrs = append(dotAddrs, value)
				case "udp":
					udpAddrs = append(udpAddrs, value)
				case "resolvers-file":
					resolverFiles = append(resolverFiles, value)
				case "resolver-policy":
					policy = value
				case "pubkey":
					pubkey = value
				case "domain":
					domainStr = value
				case "__android_vpn":
					dialerControl = dialerControlVpn
				}
			}

			localHost := os.Getenv("SS_LOCAL_HOST")
			localPort := os.Getenv("SS_LOCAL_PORT")

			if len(dohURLs)+len(dotAddrs)+len(udpAddrs)+len(resolverFiles) == 0 {
				// Fallback: check remote host/port.
				remoteHost := os.Getenv("SS_REMOTE_HOST")
				remotePort := os.Getenv("SS_REMOTE_PORT")
				if remoteHost == "" || remotePort == "" {
					fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain one of: doh, dot, udp, or resolvers-file\n")
					os.Exit(1)
				}
				udpAddrs = append(udpAddrs, net.JoinHostPort(remoteHost, remotePort))
			}
			if pubkey == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain pubkey\n")
				os.Exit(1)
			}
			if domainStr == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain domain\n")
				os.Exit(1)
			}
			if localHost == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_LOCAL_HOST environment variable not set\n")
				os.Exit(1)
			}
			if localPort == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_LOCAL_PORT environment variable not set\n")
				os.Exit(1)
			}

			// Reconstruct os.Args so the existing flag-parsing logic can be used.
			args := []string{os.Args[0]}
			for _, u := range dohURLs {
				args = append(args, "-doh", u)
			}
			for _, a := range dotAddrs {
				args = append(args, "-dot", a)
			}
			for _, a := range udpAddrs {
				args = append(args, "-udp", a)
			}
			for _, f := range resolverFiles {
				args = append(args, "-resolvers-file", f)
			}
			if policy != "" {
				args = append(args, "-resolver-policy", policy)
			}
			args = append(args, "-pubkey", pubkey, domainStr, net.JoinHostPort(localHost, localPort))
			os.Args = args
		}
	}

	var dohURLs stringSliceFlag
	var dotAddrs stringSliceFlag
	var udpAddrs stringSliceFlag
	var resolverFiles stringSliceFlag
	var pubkeyFilename string
	var pubkeyString string
	var utlsDistribution string
	var resolverPolicy string
	var doScan bool
	var scanChecks int
	var clientMTUFlag int

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-udp ADDR] (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN LOCALADDR

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -doh url1 -doh url2 -resolver-policy least-ping -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -resolvers-file resolvers.txt -scan -pubkey-file server.pub t.example.com 127.0.0.1:7000

`, os.Args[0])
		flag.PrintDefaults()
		labels := make([]string, 0, len(utlsClientHelloIDMap))
		labels = append(labels, "none")
		for _, entry := range utlsClientHelloIDMap {
			labels = append(labels, entry.Label)
		}
		fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			fmt.Fprintf(&line, "  %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				fmt.Fprintf(&line, " %s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}
	flag.Var(&dohURLs, "doh", "URL of DoH resolver (may be repeated)")
	flag.Var(&dotAddrs, "dot", "address of DoT resolver (may be repeated)")
	flag.Var(&udpAddrs, "udp", "address of UDP DNS resolver (may be repeated)")
	flag.Var(&resolverFiles, "resolvers-file", "file with one resolver per line (doh:URL, dot:host:port, udp:host:port, or bare IP/host as udp:53); may be repeated")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"choose TLS fingerprint from weighted distribution")
	flag.StringVar(&resolverPolicy, "resolver-policy", "round-robin",
		"resolver selection policy when multiple resolvers are used: round-robin, least-ping, weighted-traffic")
	flag.BoolVar(&doScan, "scan", false,
		"pre-start scan: test each resolver and keep only those that receive a valid server response")
	flag.IntVar(&scanChecks, "scan-checks", 1,
		"when -scan is used, run this many PING checks per resolver; a resolver passes only if all checks succeed (default 1, use higher for stricter scan)")
	flag.IntVar(&clientMTUFlag, "mtu", 0,
		"max question QNAME wire length in bytes (what many DPI systems limit—not full UDP size). 0 = discover per resolver. Response size is still discovered.")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		var err error
		pubkey, err = readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
	} else if pubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubkey format error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(pubkey) == 0 {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Build the merged resolver list from flags and files.
	var specs []resolverSpec
	for _, u := range dohURLs {
		specs = append(specs, resolverSpec{typ: "doh", addr: u})
	}
	for _, a := range dotAddrs {
		specs = append(specs, resolverSpec{typ: "dot", addr: a})
	}
	for _, a := range udpAddrs {
		specs = append(specs, resolverSpec{typ: "udp", addr: a})
	}
	for _, path := range resolverFiles {
		fileSpecs, err := parseResolversFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading resolvers file %q: %v\n", path, err)
			os.Exit(1)
		}
		specs = append(specs, fileSpecs...)
	}

	if len(specs) == 0 {
		fmt.Fprintf(os.Stderr, "one of -doh, -dot, -udp, or -resolvers-file is required\n")
		os.Exit(1)
	}

	// Validate policy.
	switch resolverPolicy {
	case "round-robin", "least-ping", "weighted-traffic":
	default:
		fmt.Fprintf(os.Stderr, "invalid -resolver-policy %q; must be round-robin, least-ping, or weighted-traffic\n", resolverPolicy)
		os.Exit(1)
	}

	// Build endpoints.
	endpoints := make([]*poolEndpoint, 0, len(specs))
	for _, spec := range specs {
		ep, _, err := buildEndpointFromSpec(spec, utlsClientHelloID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error initializing resolver %s %s: %v\n", spec.typ, spec.addr, err)
			os.Exit(1)
		}
		endpoints = append(endpoints, ep)
	}

	// Pre-start scan: filter to only resolvers that get a valid server response.
	if doScan {
		if scanChecks < 1 {
			scanChecks = 1
		}
		if scanChecks > 20 {
			scanChecks = 20
		}
		log.Printf("Scan: sending PING to %d resolver(s) (%d check(s) each)", len(endpoints), scanChecks)
		passed := scanResolvers(endpoints, domain, 8*time.Second, scanChecks)
		// Close endpoints that didn't pass.
		passedSet := make(map[*poolEndpoint]bool, len(passed))
		for _, ep := range passed {
			passedSet[ep] = true
		}
		for _, ep := range endpoints {
			if !passedSet[ep] {
				ep.conn.Close()
				if ep.probeConn != nil {
					ep.probeConn.Close()
				}
			}
		}
		if len(passed) == 0 {
			fmt.Fprintf(os.Stderr, "no resolvers passed -scan; check your resolver list and that the server is reachable\n")
			os.Exit(1)
		}
		log.Printf("Scan: %d/%d resolver(s) responded with PONG", len(passed), len(endpoints))
		endpoints = passed
	}

	// MTU discovery: always probe server (response) size; probe client (request) size only when -mtu not set.
	mtuTimeout := mtuProbeTimeout()
	{
		var wg sync.WaitGroup
		for _, ep := range endpoints {
			wg.Add(1)
			go func(ep *poolEndpoint) {
				defer wg.Done()
				discoverMTU(ep, domain, mtuTimeout, clientMTUFlag)
			}(ep)
		}
		wg.Wait()
	}
	if clientMTUFlag > 0 {
		log.Printf("Using client max query QNAME length %d bytes (-mtu)", clientMTUFlag)
	}

	// Drop UDP resolvers that never succeeded a server (response) MTU probe — they
	// cannot carry tunneled answers. DoH/DoT skip discoverMTU (probeConn nil); keep those.
	{
		var kept []*poolEndpoint
		for _, ep := range endpoints {
			if ep.probeConn == nil {
				kept = append(kept, ep)
				continue
			}
			maxResp, _ := ep.getMaxSizes()
			if maxResp > 0 {
				kept = append(kept, ep)
				continue
			}
			log.Printf("MTU: dropping %s (no response-size probe success; unusable for tunnel)", ep.name)
			ep.conn.Close()
			if ep.probeConn != nil {
				ep.probeConn.Close()
			}
		}
		if dropped := len(endpoints) - len(kept); dropped > 0 {
			log.Printf("MTU: removed %d/%d resolver(s) with max response wire 0", dropped, len(endpoints))
		}
		endpoints = kept
		if len(endpoints) == 0 {
			fmt.Fprintf(os.Stderr, "no resolvers left after MTU discovery (every UDP resolver failed response-size probes)\n")
			os.Exit(1)
		}
	}

	// Build the transport pconn.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	var effectiveMaxResponse, effectiveMaxRequest int

	if len(endpoints) == 1 {
		// Single resolver: keep current behavior. Close probeConn so the probe
		// socket is not leaked (pool is not used, so it would never be closed).
		effectiveMaxResponse, effectiveMaxRequest = endpoints[0].getMaxSizes()
		if effectiveMaxResponse <= 0 {
			effectiveMaxResponse = 4096
		}
		if endpoints[0].probeConn != nil {
			endpoints[0].probeConn.Close()
			endpoints[0].probeConn = nil
		}
		pconn = endpoints[0].conn
		remoteAddr = endpoints[0].addr
	} else {
		// Multiple resolvers: wrap in ResolverPool.
		probeID := turbotunnel.NewClientID()
		probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
		probeVerify := func(buf []byte) bool { return VerifyProbeResponse(buf, domain) }
		pool := NewResolverPool(endpoints, resolverPolicy, probeBuilder, probeVerify)
		pconn = pool
		remoteAddr = turbotunnel.DummyAddr{}
		effectiveMaxResponse = pool.MinMaxResponseSize(4096)
		effectiveMaxRequest = pool.MinMaxRequestSize(0)
		log.Printf("Using %d resolver(s), policy: %q", len(endpoints), resolverPolicy)
	}
	if clientMTUFlag > 0 && (effectiveMaxRequest <= 0 || clientMTUFlag < effectiveMaxRequest) {
		effectiveMaxRequest = clientMTUFlag
	}

	pconn = NewDNSPacketConn(pconn, remoteAddr, domain, effectiveMaxResponse, effectiveMaxRequest)
	err = run(pubkey, domain, localAddr, remoteAddr, pconn)
	if err != nil {
		log.Fatal(err)
	}
}
