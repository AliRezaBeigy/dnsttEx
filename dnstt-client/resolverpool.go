package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"dnsttEx/turbotunnel"
)

const (
	healthCheckInterval = 15 * time.Second
	healthCheckTimeout  = 7 * time.Second
	// After this many consecutive probe failures, mark endpoint unhealthy.
	healthCheckFailThreshold = 2
	// recvCh capacity: enough to absorb a burst from all endpoints without
	// stalling the readLoop goroutines. 4096 entries × ~4 KB each = up to
	// ~16 MB queued, well within practical limits.
	recvChCap = 4096
)

// testHookHealthCheckInterval, when non-zero, overrides healthCheckInterval in
// healthLoop so integration tests can run without waiting 15s per tick.
var testHookHealthCheckInterval time.Duration

// testHookHealthCheckTimeout, when non-zero, overrides healthCheckTimeout in
// probeEndpoint so integration tests can fail fast on unresponsive resolvers.
var testHookHealthCheckTimeout time.Duration

// resolverSpec holds a parsed resolver from flags or file.
type resolverSpec struct {
	typ  string // "doh", "dot", "udp"
	addr string // URL for doh, host:port for dot/udp
}

// poolEndpoint is one resolver endpoint inside a ResolverPool.
type poolEndpoint struct {
	// conn is the traffic connection, drained exclusively by readLoop.
	conn net.PacketConn
	// probeConn is a dedicated UDP socket used only by the health checker.
	// nil for DoH/DoT endpoints (health check is skipped for those; they
	// are assumed healthy and a warning is logged at pool creation).
	probeConn net.PacketConn
	addr      net.Addr
	name      string // human-readable label

	mu         sync.Mutex // guards healthy, lastRTT, failStreak, ranked, maxResponseSize, maxRequestSize
	healthy    bool
	lastRTT    time.Duration
	ranked     bool // true once we have at least one RTT measurement
	failStreak int

	// maxResponseSize is the max UDP response size that works through this resolver (server MTU).
	// 0 means unknown; discovery will set it or use a default.
	maxResponseSize int
	// maxRequestSize is the max request (query) size that works to this resolver (client MTU).
	// 0 means unknown.
	maxRequestSize int

	// bytesPassed counts bytes received from this endpoint (weighted-traffic).
	// Accessed only with atomic operations.
	bytesPassed atomic.Uint64
}

func (e *poolEndpoint) setHealthy(rtt time.Duration) {
	e.mu.Lock()
	e.healthy = true
	e.lastRTT = rtt
	e.ranked = true
	e.failStreak = 0
	e.mu.Unlock()
}

func (e *poolEndpoint) recordFailure() (nowUnhealthy bool) {
	e.mu.Lock()
	e.failStreak++
	if e.failStreak >= healthCheckFailThreshold {
		e.healthy = false
		nowUnhealthy = true
	}
	e.mu.Unlock()
	return
}

// markUnhealthy marks the endpoint unhealthy (e.g. when readLoop exits on permanent error).
func (e *poolEndpoint) markUnhealthy() {
	e.mu.Lock()
	e.healthy = false
	e.mu.Unlock()
}

// snapshot returns a consistent view of the health fields.
func (e *poolEndpoint) snapshot() (healthy, ranked bool, rtt time.Duration) {
	e.mu.Lock()
	healthy, ranked, rtt = e.healthy, e.ranked, e.lastRTT
	e.mu.Unlock()
	return
}

// setMaxSizes sets the discovered MTU limits for this resolver (guarded by mu).
func (e *poolEndpoint) setMaxSizes(maxResp, maxReq int) {
	e.mu.Lock()
	e.maxResponseSize = maxResp
	e.maxRequestSize = maxReq
	e.mu.Unlock()
}

// getMaxSizes returns the current max response and request sizes (guarded by mu).
func (e *poolEndpoint) getMaxSizes() (maxResp, maxReq int) {
	e.mu.Lock()
	maxResp, maxReq = e.maxResponseSize, e.maxRequestSize
	e.mu.Unlock()
	return
}

// recvResult carries one received packet from a specific endpoint.
type recvResult struct {
	buf           []byte
	n             int
	addr          net.Addr
	endpointIndex int
}

// ResolverPool implements net.PacketConn and multiplexes across multiple DNS
// resolver endpoints with pluggable selection policies and background health checks.
type ResolverPool struct {
	endpoints []*poolEndpoint
	policy    string // "round-robin", "least-ping", "weighted-traffic"

	// rrIndex is the next round-robin index; accessed atomically.
	rrIndex uint64

	recvCh    chan recvResult
	done      chan struct{}
	closeOnce sync.Once
}

// NewResolverPool creates a ResolverPool. All endpoints start as healthy.
// The pool starts a read goroutine per endpoint and a background health-checker.
// probeBuilder/probeVerify are used only for UDP endpoints (DoH/DoT endpoints
// cannot use a dedicated probe connection and are kept permanently healthy with
// a startup warning).
func NewResolverPool(endpoints []*poolEndpoint, policy string, probeBuilder func() ([]byte, error), probeVerify func([]byte) bool) *ResolverPool {
	rp := &ResolverPool{
		endpoints: endpoints,
		policy:    policy,
		recvCh:    make(chan recvResult, recvChCap),
		done:      make(chan struct{}),
	}

	// Mark all healthy at start; ranked=false until first RTT measurement.
	for _, e := range endpoints {
		e.mu.Lock()
		e.healthy = true
		e.ranked = false
		e.mu.Unlock()

		if e.probeConn == nil {
			log.Printf("resolverpool: endpoint %s (DoH/DoT) health check not supported; assumed always healthy", e.name)
		}
	}

	// Start per-endpoint read goroutines.
	for i, ep := range endpoints {
		i, ep := i, ep
		go rp.readLoop(i, ep)
	}

	// Start health checker.
	go rp.healthLoop(probeBuilder, probeVerify)

	// Log initial pool status (all healthy at start).
	rp.logPoolStatus()
	return rp
}

func (rp *ResolverPool) readLoop(idx int, ep *poolEndpoint) {
	for {
		buf := make([]byte, 4096)
		n, addr, err := ep.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-rp.done:
				return
			default:
			}
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				continue
			}
			log.Printf("resolverpool: endpoint %s ReadFrom: %v", ep.name, err)
			ep.markUnhealthy()
			return
		}
		ep.bytesPassed.Add(uint64(n))
		select {
		case rp.recvCh <- recvResult{buf: buf, n: n, addr: addr, endpointIndex: idx}:
		case <-rp.done:
			return
		}
	}
}

func (rp *ResolverPool) healthLoop(probeBuilder func() ([]byte, error), probeVerify func([]byte) bool) {
	interval := healthCheckInterval
	if testHookHealthCheckInterval != 0 {
		interval = testHookHealthCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rp.done:
			return
		case <-ticker.C:
		}
		if probeBuilder == nil || probeVerify == nil {
			continue
		}
		var wg sync.WaitGroup
		for _, ep := range rp.endpoints {
			// Only UDP endpoints have a dedicated probe connection.
			if ep.probeConn == nil {
				continue
			}
			wg.Add(1)
			ep := ep
			go func() {
				defer wg.Done()
				rp.probeEndpoint(ep, probeBuilder, probeVerify)
			}()
		}
		wg.Wait()
		rp.logPoolStatus()
	}
}

// logPoolStatus logs a one-line summary of pool health and current selection.
func (rp *ResolverPool) logPoolStatus() {
	type epSnap struct {
		ep      *poolEndpoint
		healthy bool
		ranked  bool
		rtt     time.Duration
		bytes   uint64
	}
	snaps := make([]epSnap, len(rp.endpoints))
	for i, e := range rp.endpoints {
		h, r, rtt := e.snapshot()
		snaps[i] = epSnap{ep: e, healthy: h, ranked: r, rtt: rtt, bytes: e.bytesPassed.Load()}
	}
	var healthyNames, unhealthyNames []string
	var candidates []epSnap
	for _, s := range snaps {
		if s.healthy {
			healthyNames = append(healthyNames, s.ep.name)
			candidates = append(candidates, s)
		} else {
			unhealthyNames = append(unhealthyNames, s.ep.name)
		}
	}
	nHealthy := len(healthyNames)
	total := len(rp.endpoints)
	var selected string
	if nHealthy == 0 {
		selected = "none (all unhealthy, not sending to avoid network burst)"
	} else {
		switch rp.policy {
		case "least-ping":
			var unranked []epSnap
			for _, s := range candidates {
				if !s.ranked {
					unranked = append(unranked, s)
				}
			}
			if len(unranked) > 0 {
				selected = unranked[0].ep.name + " (unranked, round-robin)"
			} else {
				best := candidates[0]
				for _, s := range candidates[1:] {
					if s.rtt < best.rtt {
						best = s
					}
				}
				selected = fmt.Sprintf("%s (rtt=%v)", best.ep.name, best.rtt)
			}
		case "weighted-traffic":
			var totalB uint64
			for _, s := range candidates {
				totalB += s.bytes
			}
			if totalB == 0 {
				selected = candidates[0].ep.name + " (round-robin until traffic)"
			} else {
				selected = fmt.Sprintf("%s (weighted)", candidates[0].ep.name)
			}
		default:
			selected = fmt.Sprintf("%s (round-robin)", candidates[0].ep.name)
		}
	}
	msg := fmt.Sprintf("resolver pool: %d/%d healthy", nHealthy, total)
	if nHealthy > 0 {
		msg += " — " + strings.Join(healthyNames, ", ")
	}
	if len(unhealthyNames) > 0 {
		msg += "; unhealthy: " + strings.Join(unhealthyNames, ", ")
	}
	msg += "; selected: " + selected
	log.Printf("resolverpool: %s", msg)
}

// probeEndpoint sends one probe on ep.probeConn (a dedicated UDP socket,
// never shared with readLoop) and updates health/RTT accordingly.
func (rp *ResolverPool) probeEndpoint(ep *poolEndpoint, probeBuilder func() ([]byte, error), probeVerify func([]byte) bool) {
	msg, err := probeBuilder()
	if err != nil {
		return
	}

	timeout := healthCheckTimeout
	if testHookHealthCheckTimeout != 0 {
		timeout = testHookHealthCheckTimeout
	}
	deadline := time.Now().Add(timeout)
	start := time.Now()

	ep.probeConn.SetDeadline(deadline)
	_, err = ep.probeConn.WriteTo(msg, ep.addr)
	if err != nil {
		ep.probeConn.SetDeadline(time.Time{})
		if ep.recordFailure() {
			log.Printf("resolverpool: endpoint %s marked unhealthy (probe write: %v)", ep.name, err)
		}
		return
	}

	buf := make([]byte, 4096)
	n, _, err := ep.probeConn.ReadFrom(buf)
	ep.probeConn.SetDeadline(time.Time{})
	if err != nil {
		if ep.recordFailure() {
			log.Printf("resolverpool: endpoint %s marked unhealthy (probe timeout: %v)", ep.name, err)
		}
		return
	}

	rtt := time.Since(start)
	if probeVerify(buf[:n]) {
		ep.setHealthy(rtt)
		log.Printf("resolverpool: endpoint %s healthy rtt=%v", ep.name, rtt)
	} else {
		if ep.recordFailure() {
			log.Printf("resolverpool: endpoint %s marked unhealthy (bad probe response)", ep.name)
		}
	}
}

// pickEndpoint selects one endpoint by the configured policy.
// Fix #7: rrIndex is updated atomically; the function only holds ep.mu briefly
// via snapshot(), avoiding nested lock ordering issues.
func (rp *ResolverPool) pickEndpoint() *poolEndpoint {
	// Snapshot health state of all endpoints without holding any pool-level lock.
	type epSnap struct {
		ep      *poolEndpoint
		healthy bool
		ranked  bool
		rtt     time.Duration
		bytes   uint64
	}
	snaps := make([]epSnap, len(rp.endpoints))
	for i, e := range rp.endpoints {
		h, r, rtt := e.snapshot()
		snaps[i] = epSnap{ep: e, healthy: h, ranked: r, rtt: rtt, bytes: e.bytesPassed.Load()}
	}

	// Build candidate list: only healthy endpoints. When none are healthy,
	// return nil so we don't send to dead resolvers and burst the network.
	candidates := snaps[:0:0]
	for _, s := range snaps {
		if s.healthy {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	switch rp.policy {
	case "least-ping":
		// Fix #6: treat unranked endpoints as a separate group. If any
		// candidates are unranked, pick among them via round-robin so that
		// all get a chance to accumulate an RTT measurement before we start
		// preferring one over another.
		var unranked []epSnap
		for _, s := range candidates {
			if !s.ranked {
				unranked = append(unranked, s)
			}
		}
		if len(unranked) > 0 {
			idx := atomic.AddUint64(&rp.rrIndex, 1) - 1
			return unranked[idx%uint64(len(unranked))].ep
		}
		best := candidates[0]
		for _, s := range candidates[1:] {
			if s.rtt < best.rtt {
				best = s
			}
		}
		return best.ep

	case "weighted-traffic":
		// Fix #2: compute total and walk using the same snapshot; no second Load().
		var total uint64
		for _, s := range candidates {
			total += s.bytes
		}
		if total == 0 {
			// No measurements yet: fall through to round-robin.
			break
		}
		r := uint64(rand.Int63n(int64(total)))
		var cum uint64
		for _, s := range candidates {
			cum += s.bytes
			if r < cum {
				return s.ep
			}
		}
		return candidates[len(candidates)-1].ep
	}

	// round-robin (default and weighted-traffic fallback).
	// Fix #7: atomic increment; no pool-level mutex needed.
	idx := atomic.AddUint64(&rp.rrIndex, 1) - 1
	return candidates[idx%uint64(len(candidates))].ep
}

// MinMaxResponseSize returns the minimum of all endpoints' maxResponseSize (server MTU).
// Used so the client can set OPT Class and the server caps responses. Returns defaultResp if any endpoint has 0.
func (rp *ResolverPool) MinMaxResponseSize(defaultResp int) int {
	if defaultResp <= 0 {
		defaultResp = 4096
	}
	min := 0
	for _, ep := range rp.endpoints {
		r, _ := ep.getMaxSizes()
		if r == 0 {
			return defaultResp
		}
		if min == 0 || r < min {
			min = r
		}
	}
	if min == 0 {
		return defaultResp
	}
	return min
}

// MinMaxRequestSize returns the minimum of all endpoints' maxRequestSize (client MTU).
// Returns defaultReq if any endpoint has 0.
func (rp *ResolverPool) MinMaxRequestSize(defaultReq int) int {
	if defaultReq <= 0 {
		defaultReq = 4096
	}
	min := 0
	for _, ep := range rp.endpoints {
		_, req := ep.getMaxSizes()
		if req == 0 {
			return defaultReq
		}
		if min == 0 || req < min {
			min = req
		}
	}
	if min == 0 {
		return defaultReq
	}
	return min
}

// WriteTo implements net.PacketConn. addr is ignored; the pool picks a resolver.
func (rp *ResolverPool) WriteTo(p []byte, addr net.Addr) (int, error) {
	ep := rp.pickEndpoint()
	if ep == nil {
		return 0, fmt.Errorf("resolverpool: no endpoints available")
	}
	return ep.conn.WriteTo(p, ep.addr)
}

// ReadFrom implements net.PacketConn. It returns the next packet from any endpoint.
func (rp *ResolverPool) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case r := <-rp.recvCh:
		n := copy(p, r.buf[:r.n])
		return n, r.addr, nil
	case <-rp.done:
		return 0, nil, fmt.Errorf("resolverpool: closed")
	}
}

// Close implements net.PacketConn.
func (rp *ResolverPool) Close() error {
	rp.closeOnce.Do(func() {
		close(rp.done)
		for _, ep := range rp.endpoints {
			ep.conn.Close()
			if ep.probeConn != nil {
				ep.probeConn.Close()
			}
		}
	})
	return nil
}

// LocalAddr implements net.PacketConn.
func (rp *ResolverPool) LocalAddr() net.Addr {
	if len(rp.endpoints) > 0 {
		return rp.endpoints[0].conn.LocalAddr()
	}
	return turbotunnel.DummyAddr{}
}

// SetDeadline implements net.PacketConn (no-op; deadlines are per-endpoint).
func (rp *ResolverPool) SetDeadline(t time.Time) error      { return nil }
func (rp *ResolverPool) SetReadDeadline(t time.Time) error  { return nil }
func (rp *ResolverPool) SetWriteDeadline(t time.Time) error { return nil }

// buildEndpointFromSpec creates a poolEndpoint from a resolverSpec.
// For UDP endpoints a dedicated probe socket (probeConn) is also opened.
// For DoH/DoT, probeConn is left nil and the health checker skips them.
func buildEndpointFromSpec(spec resolverSpec, utlsClientHelloID *utls.ClientHelloID) (*poolEndpoint, net.Addr, error) {
	switch spec.typ {
	case "doh":
		addr := turbotunnel.DummyAddr{}
		var rt http.RoundTripper
		if utlsClientHelloID == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			rt = transport
		} else {
			rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
		}
		conn, err := NewHTTPPacketConn(rt, spec.addr, 32)
		if err != nil {
			return nil, nil, err
		}
		// probeConn intentionally nil: DoH health check not supported.
		ep := &poolEndpoint{conn: conn, addr: addr, name: spec.addr}
		return ep, addr, nil

	case "dot":
		addr := turbotunnel.DummyAddr{}
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if utlsClientHelloID == nil {
			dialTLSContext = (&tls.Dialer{
				NetDialer: &net.Dialer{Control: dialerControl},
			}).DialContext
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
			}
		}
		conn, err := NewTLSPacketConn(spec.addr, dialTLSContext)
		if err != nil {
			return nil, nil, err
		}
		// probeConn intentionally nil: DoT health check not supported.
		ep := &poolEndpoint{conn: conn, addr: addr, name: spec.addr}
		return ep, addr, nil

	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", spec.addr)
		if err != nil {
			return nil, nil, err
		}
		lc := net.ListenConfig{Control: dialerControl}
		// Traffic connection — drained exclusively by readLoop.
		conn, err := lc.ListenPacket(context.Background(), "udp", ":0")
		if err != nil {
			return nil, nil, err
		}
		// Fix #1: dedicated probe socket, never shared with readLoop.
		probeConn, err := lc.ListenPacket(context.Background(), "udp", ":0")
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("opening probe socket for %s: %v", spec.addr, err)
		}
		ep := &poolEndpoint{conn: conn, probeConn: probeConn, addr: udpAddr, name: spec.addr}
		return ep, udpAddr, nil

	default:
		return nil, nil, fmt.Errorf("unknown resolver type %q", spec.typ)
	}
}
