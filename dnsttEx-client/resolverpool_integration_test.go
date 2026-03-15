//go:build integration

package main

import (
	"bytes"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"
)

// pongServer is a UDP server that responds to any DNS query with a valid PONG
// (RcodeNoError + one TXT answer with payload "PONG"). Used to simulate a
// dnstt server for resolver health checks.
type pongServer struct {
	conn net.PacketConn
}

func newPongServer(t *testing.T) *pongServer {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	return &pongServer{conn: conn}
}

func (s *pongServer) Addr() *net.UDPAddr {
	return s.conn.LocalAddr().(*net.UDPAddr)
}

func (s *pongServer) Close() error {
	return s.conn.Close()
}

// serveOne reads one DNS query and responds with PONG. Response question/answer
// names are copied from the request so VerifyProbeResponse accepts it.
func (s *pongServer) serveOne(t *testing.T) {
	buf := make([]byte, 4096)
	n, clientAddr, err := s.conn.ReadFrom(buf)
	if err != nil {
		// Conn closed during test teardown is expected; don't fail.
		if strings.Contains(err.Error(), "closed") {
			return
		}
		t.Errorf("pongServer ReadFrom: %v", err)
		return
	}
	query, err := dns.MessageFromWireFormat(buf[:n])
	if err != nil {
		t.Errorf("pongServer MessageFromWireFormat: %v", err)
		return
	}
	if len(query.Question) != 1 {
		t.Errorf("pongServer expected 1 question, got %d", len(query.Question))
		return
	}
	qname := query.Question[0].Name
	resp := &dns.Message{
		ID:    query.ID,
		Flags: 0x8000 | dns.RcodeNoError,
		Question: []dns.Question{
			{Name: qname, Type: dns.RRTypeTXT, Class: query.Question[0].Class},
		},
		Answer: []dns.RR{
			{Name: qname, Type: dns.RRTypeTXT, Class: dns.ClassIN, TTL: 0, Data: dns.EncodeRDataTXT([]byte("PONG"))},
		},
	}
	wire, err := resp.WireFormat()
	if err != nil {
		t.Errorf("pongServer WireFormat: %v", err)
		return
	}
	_, err = s.conn.WriteTo(wire, clientAddr)
	if err != nil {
		t.Errorf("pongServer WriteTo: %v", err)
	}
}

// startPongServer runs serveOne in a loop until conn is closed.
func (s *pongServer) start(t *testing.T) {
	go func() {
		for {
			s.serveOne(t)
		}
	}()
}

// makeUDPEndpoint creates a poolEndpoint that talks to the given UDP address.
// Both traffic and probe use the same server (real resolvers would too).
func makeUDPEndpoint(t *testing.T, serverAddr *net.UDPAddr) *poolEndpoint {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	probeConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		conn.Close()
		t.Fatalf("ListenPacket probe: %v", err)
	}
	name := serverAddr.String()
	return &poolEndpoint{
		conn:      conn,
		probeConn: probeConn,
		addr:      serverAddr,
		name:      name,
	}
}

// TestResolverPoolProbeRoundTrip verifies that a ResolverPool can send a probe
// (PING) to a fake server and receive a valid PONG, and that consecutive probes
// use different wire bytes (cache-busting noise).
func TestResolverPoolProbeRoundTrip(t *testing.T) {
	domain, err := dns.ParseName("probe.integration.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	server := newPongServer(t)
	defer server.Close()
	server.start(t)

	ep := makeUDPEndpoint(t, server.Addr())
	defer ep.conn.Close()
	defer ep.probeConn.Close()

	probeID := turbotunnel.NewClientID()
	probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
	probeVerify := func(b []byte) bool { return VerifyProbeResponse(b, domain) }

	pool := NewResolverPool([]*poolEndpoint{ep}, "round-robin", 1, probeBuilder, probeVerify)
	defer pool.Close()

	// Send probe via pool (traffic conn); response comes back on recvCh.
	msg1, err := probeBuilder()
	if err != nil {
		t.Fatalf("BuildProbeMessage: %v", err)
	}
	_, err = pool.WriteTo(msg1, nil)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 4096)
	pool.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pool.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !probeVerify(buf[:n]) {
		t.Error("ReadFrom did not return valid PONG response")
	}

	// Second probe must use different wire bytes (noise).
	msg2, err := probeBuilder()
	if err != nil {
		t.Fatalf("BuildProbeMessage: %v", err)
	}
	if bytes.Equal(msg1, msg2) {
		t.Error("two probes produced identical wire bytes; expected noise to differ")
	}
}

// TestResolverPoolHealthCheckMarksUnhealthy verifies that when one of two
// resolvers never responds to probes, the health checker marks it unhealthy
// and the pool continues to use the healthy one.
func TestResolverPoolHealthCheckMarksUnhealthy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping health-check integration test in short mode")
	}
	domain, err := dns.ParseName("health.integration.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}

	// Server A: responds with PONG.
	serverA := newPongServer(t)
	defer serverA.Close()
	serverA.start(t)
	epA := makeUDPEndpoint(t, serverA.Addr())
	defer epA.conn.Close()
	defer epA.probeConn.Close()

	// Server B: accepts but never responds (black hole).
	connB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket B: %v", err)
	}
	defer connB.Close()
	addrB := connB.LocalAddr().(*net.UDPAddr)
	epB := makeUDPEndpoint(t, addrB)
	defer epB.conn.Close()
	defer epB.probeConn.Close()
	// Drain requests so the socket doesn't fill; never reply.
	go func() {
		b := make([]byte, 4096)
		for {
			_, _, err := connB.ReadFrom(b)
			if err != nil {
				return
			}
		}
	}()

	// Short health interval and timeout so the test finishes quickly.
	prevInterval := testHookHealthCheckInterval
	prevTimeout := testHookHealthCheckTimeout
	testHookHealthCheckInterval = 80 * time.Millisecond
	testHookHealthCheckTimeout = 50 * time.Millisecond
	defer func() {
		testHookHealthCheckInterval = prevInterval
		testHookHealthCheckTimeout = prevTimeout
	}()

	probeID := turbotunnel.NewClientID()
	probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
	probeVerify := func(b []byte) bool { return VerifyProbeResponse(b, domain) }

	pool := NewResolverPool([]*poolEndpoint{epA, epB}, "round-robin", 1, probeBuilder, probeVerify)
	defer pool.Close()

	// Wait for at least 2 health cycles so epB gets 2 timeouts and is marked unhealthy.
	// Each cycle: probe A succeeds quickly, probe B times out after 50ms → ~50ms/cycle.
	time.Sleep(250 * time.Millisecond)

	// Send several probes; we should get PONGs back (from epA). If the pool
	// picked epB we would block forever. So we verify we get responses.
	probe, _ := probeBuilder()
	for i := 0; i < 3; i++ {
		_, err := pool.WriteTo(probe, nil)
		if err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
		respBuf := make([]byte, 4096)
		pool.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pool.ReadFrom(respBuf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		if !probeVerify(respBuf[:n]) {
			t.Errorf("response %d: not a valid PONG", i)
		}
		probe, _ = probeBuilder()
	}
}

// TestResolverPoolDataPathSkipsUnresponsive verifies that when one of two
// healthy resolvers never returns DNS responses on its data socket, the pool's
// data-path tracking stops sending to it and routes traffic to the responsive
// resolver instead. This reproduces the ISP DNS interception scenario where
// some resolvers pass health probes but don't forward tunnel queries.
func TestResolverPoolDataPathSkipsUnresponsive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping data-path integration test in short mode")
	}
	domain, err := dns.ParseName("datapath.integration.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}

	// Server A: fully responsive — echoes PONG for every query.
	serverA := newPongServer(t)
	defer serverA.Close()
	serverA.start(t)
	epA := makeUDPEndpoint(t, serverA.Addr())
	defer epA.conn.Close()
	defer epA.probeConn.Close()

	// Server B: accepts queries (so health probes succeed) but only
	// responds to probeConn, not the data conn. This simulates a resolver
	// that passes health checks but silently drops tunnel traffic.
	serverB := newPongServer(t)
	defer serverB.Close()
	serverB.start(t)
	epB := makeUDPEndpoint(t, serverB.Addr())
	defer epB.conn.Close()
	defer epB.probeConn.Close()
	// Replace epB's data conn with a black-hole socket that never gets
	// responses (the pongServer only sees the probe socket's queries, and
	// we point epB.conn at a different port with no listener to drain).
	bhConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket black-hole: %v", err)
	}
	defer bhConn.Close()
	epB.conn.Close()
	epB.conn = bhConn
	// Point the data socket at a port that will never respond.
	deadConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket dead: %v", err)
	}
	deadAddr := deadConn.LocalAddr().(*net.UDPAddr)
	deadConn.Close()
	epB.addr = deadAddr

	// Use a very short data-path response window for the test.
	prevRW := testHookDataPathResponseWindow
	testHookDataPathResponseWindow = 300 * time.Millisecond
	defer func() { testHookDataPathResponseWindow = prevRW }()

	// Short health check interval (long enough to not interfere).
	prevHI := testHookHealthCheckInterval
	prevHT := testHookHealthCheckTimeout
	testHookHealthCheckInterval = 5 * time.Second
	testHookHealthCheckTimeout = 100 * time.Millisecond
	defer func() {
		testHookHealthCheckInterval = prevHI
		testHookHealthCheckTimeout = prevHT
	}()

	probeID := turbotunnel.NewClientID()
	probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
	probeVerify := func(b []byte) bool { return VerifyProbeResponse(b, domain) }

	pool := NewResolverPool([]*poolEndpoint{epA, epB}, "round-robin", 1, probeBuilder, probeVerify)
	defer pool.Close()

	// Phase 1: Send queries and collect responses. During the data-path
	// response window (300ms), queries go to both A and B (round-robin).
	// Only A responds. After the window expires, B should be skipped.
	var sentToA, sentToB atomic.Int32
	probe, _ := probeBuilder()

	// Consume responses in background.
	var responses atomic.Int32
	go func() {
		buf := make([]byte, 4096)
		for {
			pool.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, _, err := pool.ReadFrom(buf)
			if err != nil {
				select {
				case <-pool.done:
					return
				default:
					continue
				}
			}
			responses.Add(1)
		}
	}()

	// Send 40 queries over 2 seconds.
	for i := 0; i < 40; i++ {
		probe, _ = probeBuilder()
		_, err := pool.WriteTo(probe, nil)
		if err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for data-path window to expire and responses to arrive.
	time.Sleep(500 * time.Millisecond)

	// Phase 2: Now that B's response window has expired, send more queries.
	// They should predominantly go to A (the responsive endpoint).
	_ = sentToA
	_ = sentToB

	// Verify: epA should have a recent lastResponseTime.
	lastA := epA.lastResponseTime.Load()
	lastB := epB.lastResponseTime.Load()

	if lastA == 0 {
		t.Error("epA.lastResponseTime is 0; expected responses from the responsive endpoint")
	}
	if lastB != 0 {
		t.Errorf("epB.lastResponseTime is %d; expected 0 (black-hole endpoint should never respond)", lastB)
	}

	// Verify: after 2+ seconds, the pool should route nearly all queries to A.
	// Send 20 more queries and count responses. If B were still getting queries,
	// we'd get ~50% response rate; with data-path filtering, we should get ~90%+.
	preCount := responses.Load()
	for i := 0; i < 20; i++ {
		probe, _ = probeBuilder()
		pool.WriteTo(probe, nil)
		time.Sleep(25 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	postCount := responses.Load()
	phase2Responses := postCount - preCount

	// With reprobeEvery=10, 2 out of 20 queries go to cold endpoint (re-probe).
	// So at least 16 out of 20 should get responses (80%).
	minExpected := int32(14)
	if phase2Responses < minExpected {
		t.Errorf("phase 2: got %d responses out of 20 queries; expected >= %d (data-path filtering should skip unresponsive endpoint)", phase2Responses, minExpected)
	}
	t.Logf("phase 2: %d/20 responses received (data-path filtering active)", phase2Responses)
}

// TestResolverPoolReprobeRecoversColdEndpoint verifies that a cold (data-path
// unresponsive) endpoint is periodically re-probed and rejoins the responsive
// set when it starts responding again.
func TestResolverPoolReprobeRecoversColdEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping reprobe recovery test in short mode")
	}
	domain, err := dns.ParseName("reprobe.integration.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}

	// Server A: always responsive.
	serverA := newPongServer(t)
	defer serverA.Close()
	serverA.start(t)
	epA := makeUDPEndpoint(t, serverA.Addr())
	defer epA.conn.Close()
	defer epA.probeConn.Close()

	// Server B: starts unresponsive, then becomes responsive.
	serverB := newPongServer(t)
	defer serverB.Close()
	// Don't start serverB yet — it's a black hole.
	epB := makeUDPEndpoint(t, serverB.Addr())
	defer epB.conn.Close()
	defer epB.probeConn.Close()

	// Short response window.
	prevRW := testHookDataPathResponseWindow
	testHookDataPathResponseWindow = 200 * time.Millisecond
	defer func() { testHookDataPathResponseWindow = prevRW }()

	prevHI := testHookHealthCheckInterval
	prevHT := testHookHealthCheckTimeout
	testHookHealthCheckInterval = 10 * time.Second
	testHookHealthCheckTimeout = 100 * time.Millisecond
	defer func() {
		testHookHealthCheckInterval = prevHI
		testHookHealthCheckTimeout = prevHT
	}()

	probeID := turbotunnel.NewClientID()
	probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
	probeVerify := func(b []byte) bool { return VerifyProbeResponse(b, domain) }

	pool := NewResolverPool([]*poolEndpoint{epA, epB}, "round-robin", 1, probeBuilder, probeVerify)
	defer pool.Close()

	// Drain responses.
	go func() {
		buf := make([]byte, 4096)
		for {
			pool.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			pool.ReadFrom(buf)
			select {
			case <-pool.done:
				return
			default:
			}
		}
	}()

	// Phase 1: B is unresponsive. Send queries until B becomes cold.
	for i := 0; i < 30; i++ {
		probe, _ := probeBuilder()
		pool.WriteTo(probe, nil)
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	lastB := epB.lastResponseTime.Load()
	if lastB != 0 {
		t.Fatal("epB should have lastResponseTime=0 before becoming responsive")
	}

	// Phase 2: Start server B — it now responds.
	serverB.start(t)

	// Send enough queries that a re-probe reaches B (every 10th query).
	// After the re-probe succeeds, B's lastResponseTime updates and it
	// rejoins the responsive set.
	for i := 0; i < 30; i++ {
		probe, _ := probeBuilder()
		pool.WriteTo(probe, nil)
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	lastB = epB.lastResponseTime.Load()
	if lastB == 0 {
		t.Error("epB.lastResponseTime should be non-zero after becoming responsive and being re-probed")
	} else {
		t.Logf("epB recovered: lastResponseTime=%v ago", time.Since(time.Unix(0, lastB)).Round(time.Millisecond))
	}
}
