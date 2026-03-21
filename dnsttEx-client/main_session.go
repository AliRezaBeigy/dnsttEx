// Session management and tunnel run loop for dnstt-client.
// See main.go for package documentation and entry point.

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnsttEx/dns"
	"dnsttEx/internal/kcp"
	"dnsttEx/noise"

	"github.com/xtaci/smux"
)

// sessionManager manages the KCP connection, Noise channel, and smux session,
// and can recreate them if they become closed.
type sessionManager struct {
	pubkey     []byte
	usePlain   bool // plaintext smux on KCP (no Noise)
	domain     dns.Name
	remoteAddr net.Addr
	pconn      net.PacketConn
	mtu        int

	mu       sync.RWMutex
	createMu sync.Mutex // serializes createSession so only one full handshake runs
	conn     *kcp.UDPSession
	// handshakeConn is the KCP conn while createSessionUnlocked runs, before sm.conn is set.
	// closeSession can close it so a cancelled local TCP does not block the next client on createMu.
	handshakeConn *kcp.UDPSession
	rw            io.ReadWriteCloser
	sess          *smux.Session
	conv          uint32
}

// newSessionManager creates a new session manager. If usePlain, pubkey is ignored
// and the tunnel uses no Noise (server negotiates plaintext via preamble).
func newSessionManager(pubkey []byte, domain dns.Name, remoteAddr net.Addr, pconn net.PacketConn, mtu int, usePlain bool) *sessionManager {
	return &sessionManager{
		pubkey:     pubkey,
		usePlain:   usePlain,
		domain:     domain,
		remoteAddr: remoteAddr,
		pconn:      pconn,
		mtu:        mtu,
	}
}

// closeSessionLocked closes the current session if it exists.
// reason is logged so the user knows why the connection dropped.
// Caller must hold sm.mu write lock.
func (sm *sessionManager) closeSessionLocked(reason string) {
	if sm.handshakeConn != nil {
		sm.handshakeConn.Close()
		sm.handshakeConn = nil
	}
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
		sm.conn.Close()
		sm.conn = nil
		if reason != "" {
			log.Printf("connection closed: session %08x — %s", conv, reason)
		}
	}
	sm.conv = 0
}

func (sm *sessionManager) clearHandshakeConnIf(conn *kcp.UDPSession) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.handshakeConn == conn {
		sm.handshakeConn = nil
	}
}

// handshakeDiagRWC wraps KCP during Noise.NewClient when DNSTT_HANDSHAKE_DIAG=1.
type handshakeDiagRWC struct {
	inner io.ReadWriteCloser
	conv  uint32
	nRead atomic.Uint32
	nWr   atomic.Uint32
}

func (w *handshakeDiagRWC) Read(p []byte) (int, error) {
	t0 := time.Now()
	n, err := w.inner.Read(p)
	if !dnsttHandshakeDiag() {
		return n, err
	}
	k := w.nRead.Add(1)
	wait := time.Since(t0)
	if wait >= 250*time.Millisecond || k <= 8 || k%32 == 0 {
		log.Printf("tunnel: diag KCP conv=%08x Read #%d n=%d err=%v blocked=%s (Noise readMessage waits for full server message over DNS)", w.conv, k, n, err, wait.Round(time.Millisecond))
	}
	return n, err
}

func (w *handshakeDiagRWC) Write(p []byte) (int, error) {
	if dnsttHandshakeDiag() {
		k := w.nWr.Add(1)
		if k <= 32 || k%64 == 0 {
			log.Printf("tunnel: diag KCP conv=%08x Write #%d len=%d", w.conv, k, len(p))
		}
	}
	return w.inner.Write(p)
}

func (w *handshakeDiagRWC) Close() error {
	return w.inner.Close()
}

// createSessionUnlocked creates a new KCP connection, Noise channel, and smux
// session. It does not touch sm.mu and must be called without holding it.
func (sm *sessionManager) createSessionUnlocked() (*kcp.UDPSession, io.ReadWriteCloser, *smux.Session, uint32, error) {
	dataShards, parityShards := fecShardsFromEnv()
	conn, err := kcp.NewConn2(sm.remoteAddr, nil, dataShards, parityShards, sm.pconn)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("opening KCP conn: %v", err)
	}
	conv := conn.GetConv()
	log.Printf("begin session %08x — tunnel handshake 1/4 (KCP conv allocated, configuring path)", conv)

	sm.mu.Lock()
	sm.handshakeConn = conn
	sm.mu.Unlock()

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
	conn.SetWindowSize(512, 512) // was QueueSize/2=64; larger window for high-latency DNS
	// Custom mode: suppress client ACK packets for received downstream KCP PUSH.
	conn.SetSuppressOutgoingACK(true)
	if dnsttKcpClientNreq() {
		conn.SetClientResendRequests(true)
	}
	if !conn.SetMtu(sm.mtu) {
		conn.Close()
		sm.clearHandshakeConnIf(conn)
		return nil, nil, nil, 0, fmt.Errorf("KCP SetMtu(%d) failed (minimum %d)", sm.mtu, minKCPMTU)
	}
	var rw io.ReadWriteCloser
	if sm.usePlain {
		log.Printf("tunnel: handshake %08x — step 2/4: plaintext transport (no Noise)", conv)
		if err := noise.WritePlainTransportPreamble(conn); err != nil {
			conn.Close()
			sm.clearHandshakeConnIf(conn)
			return nil, nil, nil, 0, fmt.Errorf("plain transport preamble: %w", err)
		}
		rw = conn
		log.Printf("tunnel: handshake %08x — step 3/4: Noise skipped; smux client init", conv)
	} else {
		log.Printf("tunnel: handshake %08x — step 2/4: Noise NK handshake (→ e,es … ← e,es over KCP/DNS)", conv)
		if dnsttLogRxData() {
			log.Printf("tunnel: hint %08x: DNSTT_LOG_RX_DATA shows DNSTT_TX_DATA only when a query carries tunnel payload; idle DNS polls are omitted — gaps with only RX_POLL_EMPTY are often Noise blocked in Read for the server reply", conv)
		}
		if dnsttHandshakeDiag() {
			log.Printf("tunnel: diag %08x: Noise will Write first flight then Read until full second flight; use Read blocked=… below + throttled poll lines to correlate with DNS", conv)
		}
		noiseConn := io.ReadWriteCloser(conn)
		if dnsttHandshakeDiag() {
			noiseConn = &handshakeDiagRWC{inner: conn, conv: conv}
		}
		var err error
		rw, err = noise.NewClient(noiseConn, sm.pubkey)
		if err != nil {
			conn.Close()
			sm.clearHandshakeConnIf(conn)
			return nil, nil, nil, 0, err
		}
		log.Printf("tunnel: handshake %08x — step 3/4: Noise complete; smux client init", conv)
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = 30 * time.Second
	smuxConfig.KeepAliveTimeout = 120 * time.Second
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
		_ = rw.Close()
		if !sm.usePlain {
			_ = conn.Close()
		}
		sm.clearHandshakeConnIf(conn)
		return nil, nil, nil, 0, fmt.Errorf("opening smux session: %v", err)
	}
	log.Printf("tunnel: handshake %08x — step 4/4: smux ready (multiplexing; SOCKS/stream open next)", conv)

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
	sm.closeSessionLocked("replacing with new session")
	sm.mu.Unlock()

	log.Printf("tunnel: createSession locked — running handshake steps 1–4 (others wait on createMu)")
	t0 := time.Now()
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
		sm.clearHandshakeConnIf(conn)
		log.Printf("discarding duplicate session %08x (already have %08x)", conv, sm.conv)
		return nil
	}
	sm.handshakeConn = nil
	sm.conn = conn
	sm.rw = rw
	sm.sess = sess
	sm.conv = conv
	log.Printf("tunnel: handshake %08x — done & installed in %s (openStream / SOCKS allowed)", conv, time.Since(t0).Round(time.Millisecond))
	return nil
}

// closeSession closes the current session if it exists.
// reason is logged so the user knows why the connection dropped.
func (sm *sessionManager) closeSession(reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.closeSessionLocked(reason)
}

// warmupTunnelAsync starts Noise+smux in a background goroutine so the slow first
// handshake overlaps client startup. Parallel SOCKS CONNECTs then mostly wait on
// smux OpenStream, not on createMu for a full handshake.
func (sm *sessionManager) warmupTunnelAsync() {
	go func() {
		t0 := time.Now()
		_, conv, err := sm.getSession()
		if err != nil {
			log.Printf("tunnel: async warmup failed after %s: %v", time.Since(t0).Round(time.Millisecond), err)
			return
		}
		log.Printf("tunnel: async warmup finished session %08x in %s (handshake steps 1–4 + install complete)", conv, time.Since(t0).Round(time.Millisecond))
	}()
}

// warmupTunnelSync blocks until the tunnel exists (or returns an error).
func (sm *sessionManager) warmupTunnelSync() error {
	t0 := time.Now()
	_, conv, err := sm.getSession()
	if err != nil {
		return err
	}
	log.Printf("tunnel: sync warmup finished session %08x in %s (handshake steps 1–4 + install complete)", conv, time.Since(t0).Round(time.Millisecond))
	return nil
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
	errStrLower := strings.ToLower(errStr)
	isClosedError := errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, smux.ErrTimeout) ||
		errors.Is(err, smux.ErrGoAway) ||
		strings.Contains(errStr, "closed pipe") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStrLower, "timeout") ||
		strings.Contains(errStrLower, "stream id overflows") ||
		err == io.EOF

	if !isClosedError {
		return nil, 0, fmt.Errorf("session %08x opening stream: %v", conv, err)
	}

	log.Printf("connection closed: session %08x — session dead (e.g. keepalive timeout or remote close), recreating: %v", conv, err)
	// Clear the dead session only if it hasn't already been replaced by
	// another goroutine.
	sm.mu.Lock()
	if sm.sess == sess {
		sm.closeSessionLocked("session dead, recreating")
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
