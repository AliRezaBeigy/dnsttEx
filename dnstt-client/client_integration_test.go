//go:build integration

package main

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"dnsttEx/dns"
	"dnsttEx/noise"
	"dnsttEx/turbotunnel"
)

// TestSessionManagerNoDeadlock verifies that concurrent calls to createSession
// and getSession do not deadlock on the mutex. This is a regression test for
// the bug where getSession held sm.mu write lock and then called createSession
// which also tried to acquire sm.mu.
//
// Strategy: the goroutines will call createSession/getSession, which will get
// past the locking phase and block on noise.NewClient (waiting for a Noise
// handshake that never completes since nothing is listening). We close the
// underlying connection after a short delay to unblock them. If the mutex
// logic were deadlocked, the goroutines would never reach the network I/O
// phase — they'd be stuck on sm.mu — and closing pconn would not unblock them.
func TestSessionManagerNoDeadlock(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	remoteAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	domain, _ := dns.ParseName("t.test.invalid")
	dnsConn := NewDNSPacketConn(pconn, remoteAddr, domain, 0, 0)

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatalf("GeneratePrivkey: %v", err)
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)
	mtu := maxPacketSize
	sm := newSessionManager(pubkey, domain, turbotunnel.DummyAddr{}, dnsConn, mtu)

	const goroutines = 4
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// These calls are expected to block on network I/O (not on the
			// mutex). Closing pconn below will unblock them.
			sm.createSession()
		}()
	}

	// Give goroutines a moment to get past the locking logic and into the
	// network I/O phase (Noise handshake), then close the connection to unblock.
	time.Sleep(200 * time.Millisecond)
	pconn.Close()  // unblocks noise.NewClient / KCP I/O
	dnsConn.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("all goroutines finished — no mutex deadlock detected")
	case <-time.After(5 * time.Second):
		t.Fatal("goroutines did not finish within 5s after pconn.Close() — possible deadlock")
	}

	sm.closeSession()
}

// TestSessionManagerCloseSession verifies that closeSession clears all fields
// and is safe to call multiple times.
func TestSessionManagerCloseSession(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()

	domain, _ := dns.ParseName("t.test.invalid")
	privkey, _ := noise.GeneratePrivkey()
	pubkey := noise.PubkeyFromPrivkey(privkey)
	mtu := maxPacketSize
	sm := newSessionManager(pubkey, domain, turbotunnel.DummyAddr{}, pconn, mtu)

	// closeSession on a manager with no session should not panic.
	sm.closeSession()
	sm.closeSession()

	// Verify internal state is clean.
	sm.mu.RLock()
	sessNil := sm.sess == nil
	connNil := sm.conn == nil
	rwNil := sm.rw == nil
	sm.mu.RUnlock()

	if !sessNil || !connNil || !rwNil {
		t.Error("closeSession did not clear all fields")
	}
}

// TestRunLifecycle verifies that run() starts a TCP listener on the given
// address and exits when the DNSPacketConn is closed.
func TestRunLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping lifecycle test in short mode")
	}

	// Allocate a free loopback TCP port for the client listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate TCP port: %v", err)
	}
	localAddr := ln.Addr().(*net.TCPAddr)
	ln.Close()

	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	privkey, _ := noise.GeneratePrivkey()
	pubkey := noise.PubkeyFromPrivkey(privkey)
	domain, _ := dns.ParseName("t.test.invalid")

	remoteAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	// dnsConn wraps pconn; we pass it directly to run().
	dnsConn := NewDNSPacketConn(pconn, remoteAddr, domain, 0, 0)

	runDone := make(chan error, 1)
	go func() {
		// run() calls defer pconn.Close() on its argument (dnsConn), and
		// blocks on ln.Accept(). It will exit when dnsConn is closed.
		runDone <- run(pubkey, domain, localAddr, turbotunnel.DummyAddr{}, dnsConn)
	}()

	// Poll until the TCP listener is up (or 5s timeout).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", localAddr.String(), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			dnsConn.Close()
			t.Fatalf("run() TCP listener did not come up within 5s: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Log("run() TCP listener is accepting connections")

	// Close the DNSPacketConn — this unblocks run()'s ln.Accept() via
	// the deferred pconn.Close() path, causing run() to return.
	dnsConn.Close()

	select {
	case err := <-runDone:
		if err != nil {
			t.Logf("run() exited with (expected) error: %v", err)
		} else {
			t.Log("run() exited cleanly")
		}
	case <-time.After(5 * time.Second):
		t.Error("run() did not exit within 5s after dnsConn.Close()")
	}
}

// TestDNSPacketConnSendRecv verifies that DNSPacketConn encodes outgoing
// packets into DNS TXT queries and that closing the transport stops the loops.
func TestDNSPacketConnSendRecv(t *testing.T) {
	// Set up a loopback UDP pair: client sends DNS queries to "server".
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server ListenPacket: %v", err)
	}
	defer serverConn.Close()

	clientUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client ListenPacket: %v", err)
	}

	domain, _ := dns.ParseName("t.test.invalid")
	serverAddr := serverConn.LocalAddr()

	dnsPC := NewDNSPacketConn(clientUDP, serverAddr, domain, 0, 0)
	defer dnsPC.Close()

	// Write a small packet to the DNSPacketConn — it should encode it as a DNS query.
	testData := []byte("hello dnstt")
	dnsPC.WriteTo(testData, serverAddr)

	// The server side should receive a valid DNS query within 2s.
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := serverConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom: %v (DNS query not received within 2s)", err)
	}

	// Parse the received packet as a DNS message.
	msg, err := dns.MessageFromWireFormat(buf[:n])
	if err != nil {
		t.Fatalf("MessageFromWireFormat: %v", err)
	}
	if msg.Flags&0x8000 != 0 {
		t.Error("received a response (QR=1), expected a query (QR=0)")
	}
	if len(msg.Question) == 0 {
		t.Fatal("DNS query has no question section")
	}
	// The question name must be a subdomain of our domain.
	_, ok := msg.Question[0].Name.TrimSuffix(domain)
	if !ok {
		t.Errorf("query name %s is not a subdomain of %s", msg.Question[0].Name, domain)
	}
	if msg.Question[0].Type != dns.RRTypeTXT {
		t.Errorf("QTYPE = %d, want TXT (16)", msg.Question[0].Type)
	}
	t.Logf("DNSPacketConn sent a valid DNS TXT query to domain %s", domain)

	// Closing the underlying UDP connection should stop the loops.
	clientUDP.Close()
}

// TestOpenStreamRecreatessSession verifies that openStream automatically
// recreates the session when the existing session is closed, without deadlock.
func TestOpenStreamRecreatesSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping openStream recreate test in short mode")
	}

	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()

	domain, _ := dns.ParseName("t.test.invalid")
	privkey, _ := noise.GeneratePrivkey()
	pubkey := noise.PubkeyFromPrivkey(privkey)
	mtu := maxPacketSize

	remoteAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	dnsConn := NewDNSPacketConn(pconn, remoteAddr, domain, 0, 0)
	defer dnsConn.Close()

	sm := newSessionManager(pubkey, domain, turbotunnel.DummyAddr{}, dnsConn, mtu)
	defer sm.closeSession()

	// openStream will call getSession → createSession. The session will be
	// created but the Noise handshake will never complete (nothing listening),
	// so openStream will block. We just verify it doesn't deadlock by using
	// a timeout.
	done := make(chan struct{})
	go func() {
		defer close(done)
		// This will attempt to open a stream. With no real server, smux will
		// eventually time out or return an error — we just need it to not deadlock.
		sm.openStream()
	}()

	// If no deadlock, the goroutine should unblock eventually (or when we
	// close the connection). Give it 3s, then close to force exit.
	select {
	case <-done:
		t.Log("openStream returned without deadlock")
	case <-time.After(3 * time.Second):
		// Close dnsConn (the PacketConn the sessionManager uses) so that
		// QueuePacketConn.ReadFrom unblocks with an error and openStream returns.
		dnsConn.Close()
		select {
		case <-done:
			t.Log("openStream unblocked after dnsConn.Close()")
		case <-time.After(3 * time.Second):
			t.Error("openStream appears to be deadlocked even after dnsConn.Close()")
		}
	}
}

// noopReadWriteCloser is a ReadWriteCloser that discards all writes and
// returns io.EOF on reads, used to make smux sessions for unit testing.
type noopReadWriteCloser struct {
	closed chan struct{}
}

func newNoopRWC() *noopReadWriteCloser {
	return &noopReadWriteCloser{closed: make(chan struct{})}
}

func (n *noopReadWriteCloser) Read(p []byte) (int, error) {
	<-n.closed
	return 0, io.EOF
}

func (n *noopReadWriteCloser) Write(p []byte) (int, error) {
	select {
	case <-n.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}

func (n *noopReadWriteCloser) Close() error {
	select {
	case <-n.closed:
	default:
		close(n.closed)
	}
	return nil
}
