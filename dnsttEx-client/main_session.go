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
	"strconv"
	"strings"
	"sync"
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
// reason is logged so the user knows why the connection dropped.
// Caller must hold sm.mu write lock.
func (sm *sessionManager) closeSessionLocked(reason string) {
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
	sm.closeSessionLocked("replacing with new session")
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
// reason is logged so the user knows why the connection dropped.
func (sm *sessionManager) closeSession(reason string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.closeSessionLocked(reason)
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

// Logging constants for DNSTT_LOG_RX_DATA.
const (
	peekSize             = 4096
	logFirstChunks       = 5
	minChunkBytesForCount = 4
)

// copyUpstreamWithLog copies from local to stream and, when DNSTT_LOG_RX_DATA is set,
// logs the first few chunks using FormatUpstreamForSocksLog so you see SOCKS greeting,
// SOCKS CONNECT, and HTTP request.
func copyUpstreamWithLog(stream *smux.Stream, local *net.TCPConn, conv uint32, streamID uint32) (int64, error) {
	buf := make([]byte, peekSize)
	var total int64
	logCount := 0
	for logCount < logFirstChunks {
		n, err := local.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if dnsttLogRxData() {
				desc := FormatUpstreamForSocksLog(chunk)
				log.Printf("DNSTT_CLIENT_UPSTREAM stream %08x:%d | %s", conv, streamID, desc)
				if n >= minChunkBytesForCount {
					logCount++
				}
			}
			if _, werr := stream.Write(chunk); werr != nil {
				return total + int64(n), werr
			}
			total += int64(n)
			continue
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		// n == 0, err == nil: exit chunk loop and copy rest
		break
	}
	copied, err := io.Copy(stream, local)
	return total + copied, err
}

const firstDownstreamGatherMin = 10

// copyDownstreamWithLog copies from stream to local and, when DNSTT_LOG_RX_DATA is set,
// logs the first few chunks using FormatDownstreamForSocksLog so you see SOCKS reply
// and HTTP response.
func copyDownstreamWithLog(local *net.TCPConn, stream *smux.Stream, conv uint32, streamID uint32) (int64, error) {
	buf := make([]byte, peekSize)
	var total int64
	logCount := 0
	for logCount < logFirstChunks {
		n, err := stream.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if dnsttLogRxData() && logCount == 0 && n < firstDownstreamGatherMin && n < len(buf) {
				stream.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				nn, _ := stream.Read(buf[n:])
				stream.SetReadDeadline(time.Time{})
				if nn > 0 {
					chunk = buf[:n+nn]
					n += nn
				}
			}
			if dnsttLogRxData() {
				desc := FormatDownstreamForSocksLog(chunk)
				log.Printf("DNSTT_CLIENT_DOWNSTREAM stream %08x:%d | %s", conv, streamID, desc)
				if len(chunk) >= minChunkBytesForCount {
					logCount++
				}
			}
			if _, werr := local.Write(chunk); werr != nil {
				return total + int64(len(chunk)), werr
			}
			total += int64(len(chunk))
			continue
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		break
	}
	copied, err := io.Copy(local, stream)
	return total + copied, err
}

func handle(local *net.TCPConn, sm *sessionManager) error {
	stream, conv, err := sm.openStream()
	if err != nil {
		return fmt.Errorf("opening stream: %v", err)
	}
	defer func() {
		log.Printf("connection closed: stream %08x:%d — ended", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := copyUpstreamWithLog(stream, local, conv, stream.ID())
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("connection closed: stream %08x:%d — local→tunnel write failed: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
	}()
	go func() {
		defer wg.Done()
		_, err := copyDownstreamWithLog(local, stream, conv, stream.ID())
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("connection closed: stream %08x:%d — tunnel→local read failed (remote may have closed): %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

// packetConnWithDone is implemented by PacketConns that signal when they are closed.
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

	sm := newSessionManager(pubkey, domain, remoteAddr, pconn, mtu)
	defer sm.closeSession("tunnel shutting down")

	if dpc, ok := pconn.(packetConnWithDone); ok {
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
					log.Printf("connection closed: tunnel transport closed (rejecting new connection)")
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
