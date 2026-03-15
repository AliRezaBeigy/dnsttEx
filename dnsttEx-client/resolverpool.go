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

	"dnsttEx/turbotunnel"

	utls "github.com/refraction-networking/utls"
)

const (
	healthCheckInterval = 60 * time.Second
	healthCheckTimeout  = 7 * time.Second
	// After this many consecutive probe failures, mark endpoint unhealthy.
	healthCheckFailThreshold = 2
	// recvCh capacity: enough to absorb a burst from all endpoints without
	// stalling the readLoop goroutines. 4096 entries × ~4 KB each = up to
	// ~16 MB queued, well within practical limits.
	recvChCap = 4096

	// Data-path responsiveness: endpoints that haven't returned any DNS
	// response within this window are skipped by pickEndpoint. This catches
	// resolvers that pass health probes but silently drop tunnel queries
	// (common with ISP DNS interception across multiple backend resolvers).
	dataPathResponseWindow = 20 * time.Second
	// Every reprobeEvery-th query, send one query to a "cold" (unresponsive)
	// endpoint to check if it has recovered.
	reprobeEvery = 10

	// Endpoints with >= servfailColdThreshold consecutive SERVFAILs (without
	// an intervening success) are treated as "cold" by pickEndpoint. This
	// catches resolvers that consistently return SERVFAIL for tunnel data
	// queries. The threshold must be high enough to tolerate intermittent
	// SERVFAILs (e.g. 27% rate → P(5 consecutive) ≈ 0.1%) without
	// deprioritizing a resolver that is otherwise the only one working.
	servfailColdThreshold = 5
)

// testHookHealthCheckInterval, when non-zero, overrides healthCheckInterval in
// healthLoop so integration tests can run without waiting 15s per tick.
var testHookHealthCheckInterval time.Duration

// testHookHealthCheckTimeout, when non-zero, overrides healthCheckTimeout in
// probeEndpoint so integration tests can fail fast on unresponsive resolvers.
var testHookHealthCheckTimeout time.Duration

// testHookDataPathResponseWindow, when non-zero, overrides dataPathResponseWindow
// in pickEndpoint so tests can verify data-path filtering without long waits.
var testHookDataPathResponseWindow time.Duration

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
	// maxRequestSize is the max question QNAME wire length (client MTU / DPI limit).
	// 0 means unknown.
	maxRequestSize int

	// bytesPassed counts bytes received from this endpoint (weighted-traffic).
	// Accessed only with atomic operations.
	bytesPassed atomic.Uint64

	// lastResponseTime is the UnixNano timestamp of the most recent DNS
	// response received from this endpoint's data socket. Updated atomically
	// by readLoop; read by pickEndpoint for data-path filtering.
	lastResponseTime atomic.Int64

	// servfailStreak counts consecutive SERVFAIL (rcode 2) responses from
	// this endpoint without an intervening successful response.
	// ReportServfail increments it; ConfirmDataPath resets it to 0.
	// pickEndpoint treats endpoints with servfailStreak >= servfailColdThreshold
	// as "cold" even if lastResponseTime is recent.
	servfailStreak atomic.Int32

	// servfailTotal is the lifetime SERVFAIL count (for logging).
	servfailTotal atomic.Uint64
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

	// sendParallel is how many resolvers to use per send (1 = single resolver).
	// When > 1, the same packet is sent to that many resolvers so at least one may succeed.
	sendParallel int

	// rrIndex is the next round-robin index; accessed atomically.
	rrIndex uint64

	// sendMu guards pendingSends. NextSendMTU picks endpoint(s) and stores them here;
	// the next WriteTo sends to those same endpoint(s) so the query (built with the
	// minimum MTU of the chosen endpoints) goes to the correct resolver(s).
	sendMu       sync.Mutex
	pendingSends []*poolEndpoint

	// reprobeIdx is the next round-robin index for re-probing cold (data-path
	// unresponsive) endpoints; accessed atomically.
	reprobeIdx uint64

	recvCh    chan recvResult
	done      chan struct{}
	closeOnce sync.Once
}

// NewResolverPool creates a ResolverPool. All endpoints start as healthy.
// The pool starts a read goroutine per endpoint and a background health-checker.
// probeBuilder/probeVerify are used only for UDP endpoints (DoH/DoT endpoints
// cannot use a dedicated probe connection and are kept permanently healthy with
// a startup warning).
// sendParallel is how many resolvers to use per send (1 = current behavior; >1 sends
// the same packet to that many resolvers in parallel so at least one may succeed).
func NewResolverPool(endpoints []*poolEndpoint, policy string, sendParallel int, probeBuilder func() ([]byte, error), probeVerify func([]byte) bool) *ResolverPool {
	if sendParallel < 1 {
		sendParallel = 1
	}
	rp := &ResolverPool{
		endpoints:    endpoints,
		policy:       policy,
		sendParallel: sendParallel,
		recvCh:       make(chan recvResult, recvChCap),
		done:         make(chan struct{}),
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
		ep.lastResponseTime.Store(time.Now().UnixNano())
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
	// Count data-path cold endpoints among healthy ones.
	respWindow := dataPathResponseWindow
	if testHookDataPathResponseWindow != 0 {
		respWindow = testHookDataPathResponseWindow
	}
	var coldNames []string
	for _, s := range candidates {
		last := s.ep.lastResponseTime.Load()
		sfStreak := s.ep.servfailStreak.Load()
		isCold := (last == 0 || time.Since(time.Unix(0, last)) >= respWindow) ||
			sfStreak >= servfailColdThreshold
		if isCold {
			label := s.ep.name
			if sfStreak >= servfailColdThreshold {
				label += fmt.Sprintf(" (SERVFAIL×%d)", sfStreak)
			}
			coldNames = append(coldNames, label)
		}
	}

	msg := fmt.Sprintf("resolver pool: %d/%d healthy", nHealthy, total)
	if nHealthy > 0 {
		msg += " — " + strings.Join(healthyNames, ", ")
	}
	if len(unhealthyNames) > 0 {
		msg += "; unhealthy: " + strings.Join(unhealthyNames, ", ")
	}
	if len(coldNames) > 0 {
		msg += fmt.Sprintf("; data-path cold (%d): %s", len(coldNames), strings.Join(coldNames, ", "))
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
	if dnsttDebug() {
		log.Printf("DNSTT_DEBUG: health PING query %s (hex):\n%s", ep.name, dnsttDebugHexDump(msg, 0))
	}

	buf := make([]byte, 4096)
	n, _, err := ep.probeConn.ReadFrom(buf)
	ep.probeConn.SetDeadline(time.Time{})
	if dnsttDebug() && err == nil {
		log.Printf("DNSTT_DEBUG: health PONG response %s (hex):\n%s", ep.name, dnsttDebugHexDump(buf[:n], 0))
	}
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

// epSnap is a snapshot of an endpoint's health state (used by pickEndpoint and pickNEndpoints).
type epSnap struct {
	ep      *poolEndpoint
	healthy bool
	ranked  bool
	rtt     time.Duration
	bytes   uint64
}

// getCandidates returns healthy endpoints, filtered by data-path responsiveness
// (responsive preferred; cold endpoints re-probed occasionally). Caller must not modify.
func (rp *ResolverPool) getCandidates() []epSnap {
	snaps := make([]epSnap, len(rp.endpoints))
	for i, e := range rp.endpoints {
		h, r, rtt := e.snapshot()
		snaps[i] = epSnap{ep: e, healthy: h, ranked: r, rtt: rtt, bytes: e.bytesPassed.Load()}
	}
	candidates := snaps[:0:0]
	for _, s := range snaps {
		if s.healthy {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	respWindow := dataPathResponseWindow
	if testHookDataPathResponseWindow != 0 {
		respWindow = testHookDataPathResponseWindow
	}
	var responsive, cold []epSnap
	for _, s := range candidates {
		last := s.ep.lastResponseTime.Load()
		sfStreak := s.ep.servfailStreak.Load()
		isCold := (last == 0 || time.Since(time.Unix(0, last)) >= respWindow) ||
			sfStreak >= servfailColdThreshold
		if isCold {
			cold = append(cold, s)
		} else {
			responsive = append(responsive, s)
		}
	}
	if len(responsive) > 0 && len(cold) > 0 {
		queryNum := atomic.AddUint64(&rp.reprobeIdx, 1)
		if queryNum%uint64(reprobeEvery) == 0 {
			coldIdx := (queryNum / uint64(reprobeEvery)) % uint64(len(cold))
			return []epSnap{cold[coldIdx]}
		}
		return responsive
	}
	return candidates
}

// pickNEndpoints selects up to n endpoints for parallel send. Uses the same
// candidate list as pickEndpoint but returns min(n, len(candidates)) in
// round-robin order so the same packet can be sent to multiple resolvers.
func (rp *ResolverPool) pickNEndpoints(n int) []*poolEndpoint {
	candidates := rp.getCandidates()
	if len(candidates) == 0 {
		return nil
	}
	if n <= 0 {
		n = 1
	}
	k := n
	if k > len(candidates) {
		k = len(candidates)
	}
	idx := atomic.AddUint64(&rp.rrIndex, uint64(k)) - uint64(k)
	out := make([]*poolEndpoint, k)
	for i := 0; i < k; i++ {
		out[i] = candidates[(int(idx)+i)%len(candidates)].ep
	}
	return out
}

// pickEndpoint selects one endpoint by the configured policy.
// Fix #7: rrIndex is updated atomically; the function only holds ep.mu briefly
// via snapshot(), avoiding nested lock ordering issues.
func (rp *ResolverPool) pickEndpoint() *poolEndpoint {
	candidates := rp.getCandidates()
	if len(candidates) == 0 {
		return nil
	}

	switch rp.policy {
	case "least-ping":
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
		var total uint64
		for _, s := range candidates {
			total += s.bytes
		}
		if total == 0 {
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

// NextSendMTU returns the max response size and max QNAME length for the
// endpoint(s) that will be used for the next WriteTo. When sendParallel > 1,
// returns the minimum MTU among the chosen endpoints so the same query can be
// sent to all. The caller must build the query with those limits and then call
// WriteTo; the same packet is sent to all chosen endpoint(s).
func (rp *ResolverPool) NextSendMTU() (maxResponseSize, maxRequestSize int) {
	rp.sendMu.Lock()
	var eps []*poolEndpoint
	if rp.sendParallel > 1 {
		eps = rp.pickNEndpoints(rp.sendParallel)
	} else {
		ep := rp.pickEndpoint()
		if ep != nil {
			eps = []*poolEndpoint{ep}
		}
	}
	if len(eps) == 0 {
		rp.sendMu.Unlock()
		return 0, 0
	}
	rp.pendingSends = eps
	maxResp, maxReq := 0, 0
	for i, ep := range eps {
		r, q := ep.getMaxSizes()
		if r <= 0 {
			r = 4096
		}
		if q <= 0 {
			q = 4096
		}
		if i == 0 || r < maxResp {
			maxResp = r
		}
		if i == 0 || q < maxReq {
			maxReq = q
		}
	}
	rp.sendMu.Unlock()
	if maxResp <= 0 {
		maxResp = 4096
	}
	if maxReq <= 0 {
		maxReq = 4096
	}
	return maxResp, maxReq
}

// WriteTo implements net.PacketConn. addr is ignored; the pool picks resolver(s).
// If NextSendMTU was called just before this, the same endpoint(s) are used.
// When sendParallel > 1, the same packet is sent to all chosen endpoints in
// parallel; the send succeeds if at least one WriteTo succeeds.
func (rp *ResolverPool) WriteTo(p []byte, addr net.Addr) (int, error) {
	rp.sendMu.Lock()
	eps := rp.pendingSends
	rp.pendingSends = nil
	if len(eps) == 0 {
		if rp.sendParallel > 1 {
			eps = rp.pickNEndpoints(rp.sendParallel)
		} else {
			ep := rp.pickEndpoint()
			if ep != nil {
				eps = []*poolEndpoint{ep}
			}
		}
	}
	rp.sendMu.Unlock()
	if len(eps) == 0 {
		return 0, fmt.Errorf("resolverpool: no endpoints available")
	}
	if len(eps) == 1 {
		return eps[0].conn.WriteTo(p, eps[0].addr)
	}
	// Send to all in parallel; succeed if at least one succeeds.
	type result struct {
		n   int
		err error
	}
	results := make(chan result, len(eps))
	for _, ep := range eps {
		ep := ep
		go func() {
			n, err := ep.conn.WriteTo(p, ep.addr)
			results <- result{n, err}
		}()
	}
	var lastErr error
	successN := 0
	for i := 0; i < len(eps); i++ {
		res := <-results
		if res.err == nil {
			successN = res.n
		} else {
			lastErr = res.err
		}
	}
	if successN > 0 {
		return successN, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("resolverpool: no endpoint succeeded")
	}
	return 0, lastErr
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

// ConfirmDataPath resets the SERVFAIL streak for the endpoint matching addr,
// confirming it can successfully forward tunnel traffic. Called by recvLoop
// on successful (rcode=0) DNS responses.
func (rp *ResolverPool) ConfirmDataPath(addr net.Addr) {
	addrStr := addr.String()
	for _, ep := range rp.endpoints {
		if ep.addr.String() == addrStr {
			ep.servfailStreak.Store(0)
			return
		}
	}
}

// ReportServfail increments the SERVFAIL streak for the endpoint matching addr.
// When the streak reaches servfailColdThreshold, pickEndpoint treats the
// endpoint as "cold" and deprioritizes it. The resolver passes health probes
// but cannot forward tunnel traffic to the authoritative server.
func (rp *ResolverPool) ReportServfail(addr net.Addr) {
	addrStr := addr.String()
	for _, ep := range rp.endpoints {
		if ep.addr.String() == addrStr {
			streak := ep.servfailStreak.Add(1)
			total := ep.servfailTotal.Add(1)
			if streak == servfailColdThreshold {
				log.Printf("resolverpool: endpoint %s SERVFAIL streak=%d (threshold) total=%d — deprioritizing",
					ep.name, streak, total)
			} else if total == 1 || total%20 == 0 {
				log.Printf("resolverpool: endpoint %s SERVFAIL streak=%d total=%d",
					ep.name, streak, total)
			}
			return
		}
	}
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
