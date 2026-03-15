package main

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"dnsttEx/turbotunnel"
)

// recordingPacketConn wraps a net.PacketConn and records the last WriteTo payload.
// ReadFrom blocks until Close so pool readLoop does not exit during the test.
type recordingPacketConn struct {
	net.PacketConn
	lastWrite []byte
	mu        sync.Mutex
}

func (r *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	r.mu.Lock()
	r.lastWrite = append(r.lastWrite[:0], p...)
	r.mu.Unlock()
	return r.PacketConn.WriteTo(p, addr)
}

func (r *recordingPacketConn) getLastWrite() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.lastWrite...)
}

// TestResolverPoolNextSendMTUWriteToSameEndpoint verifies that after NextSendMTU(),
// the next WriteTo sends to the same endpoint (so the query built with that endpoint's
// MTU is sent to the correct resolver).
func TestResolverPoolNextSendMTUWriteToSameEndpoint(t *testing.T) {
	// Two UDP listeners as underlying conns; we wrap them to record writes.
	conn0, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn0.Close()
	conn1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn1.Close()

	rec0 := &recordingPacketConn{PacketConn: conn0}
	rec1 := &recordingPacketConn{PacketConn: conn1}

	ep0 := &poolEndpoint{
		conn:  rec0,
		addr:  conn0.LocalAddr(),
		name:  "ep0",
		probeConn: nil,
	}
	ep0.setMaxSizes(100, 100)

	ep1 := &poolEndpoint{
		conn:  rec1,
		addr:  conn1.LocalAddr(),
		name:  "ep1",
		probeConn: nil,
	}
	ep1.setMaxSizes(200, 200)

	// Both endpoints must look data-path responsive; otherwise after first WriteTo only ep0
	// has lastResponseTime set and pickEndpoint sticks to ep0.
	now := time.Now().UnixNano()
	ep0.lastResponseTime.Store(now)
	ep1.lastResponseTime.Store(now)

	pool := NewResolverPool(
		[]*poolEndpoint{ep0, ep1},
		"round-robin",
		1, nil, nil,
	)
	defer pool.Close()

	// First send: NextSendMTU should pick ep0 (round-robin index 0), then WriteTo goes to ep0.
	maxResp, maxReq := pool.NextSendMTU()
	if maxResp != 100 || maxReq != 100 {
		t.Fatalf("first NextSendMTU() = (%d, %d), want (100, 100)", maxResp, maxReq)
	}
	payload1 := []byte("query1")
	n, err := pool.WriteTo(payload1, turbotunnel.DummyAddr{})
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload1) {
		t.Errorf("WriteTo wrote %d bytes, want %d", n, len(payload1))
	}
	got0 := rec0.getLastWrite()
	got1 := rec1.getLastWrite()
	if !bytes.Equal(got0, payload1) {
		t.Errorf("ep0 (rec0) received %q, want %q", got0, payload1)
	}
	if len(got1) != 0 {
		t.Errorf("ep1 (rec1) should not have received; got %q", got1)
	}

	// Second send: NextSendMTU should pick ep1, then WriteTo goes to ep1.
	maxResp, maxReq = pool.NextSendMTU()
	if maxResp != 200 || maxReq != 200 {
		t.Fatalf("second NextSendMTU() = (%d, %d), want (200, 200)", maxResp, maxReq)
	}
	payload2 := []byte("query2")
	n, err = pool.WriteTo(payload2, turbotunnel.DummyAddr{})
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	got0 = rec0.getLastWrite()
	got1 = rec1.getLastWrite()
	if !bytes.Equal(got1, payload2) {
		t.Errorf("ep1 (rec1) received %q, want %q", got1, payload2)
	}
	// rec0 still has payload1 from before
	if !bytes.Equal(got0, payload1) {
		t.Errorf("ep0 (rec0) last write changed to %q", got0)
	}
}

// TestResolverPoolWriteToWithoutNextSendMTU verifies that WriteTo still works when
// NextSendMTU was not called (picks an endpoint normally).
func TestResolverPoolWriteToWithoutNextSendMTU(t *testing.T) {
	conn0, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn0.Close()

	rec0 := &recordingPacketConn{PacketConn: conn0}
	ep0 := &poolEndpoint{
		conn:     rec0,
		addr:     conn0.LocalAddr(),
		name:     "ep0",
		probeConn: nil,
	}
	ep0.setMaxSizes(512, 512)

	pool := NewResolverPool([]*poolEndpoint{ep0}, "round-robin", 1, nil, nil)
	defer pool.Close()

	// No NextSendMTU call; WriteTo should still send (pick endpoint as usual).
	payload := []byte("standalone write")
	n, err := pool.WriteTo(payload, turbotunnel.DummyAddr{})
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo wrote %d bytes, want %d", n, len(payload))
	}
	got := rec0.getLastWrite()
	if !bytes.Equal(got, payload) {
		t.Errorf("received %q, want %q", got, payload)
	}
}
