//go:build integration

package main

import (
	"bytes"
	"net"
	"strings"
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

	pool := NewResolverPool([]*poolEndpoint{ep}, "round-robin", probeBuilder, probeVerify)
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

	pool := NewResolverPool([]*poolEndpoint{epA, epB}, "round-robin", probeBuilder, probeVerify)
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
