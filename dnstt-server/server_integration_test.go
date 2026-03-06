//go:build integration

package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"
)

// base36Encode encodes src into Base36 (0-9a-v, 5 bits/symbol) for name-based tests.
func base36EncodeTest(src []byte) []byte {
	const alphabet = "0123456789abcdefghijklmnopqrstuv"
	n := (len(src)*8 + 4) / 5
	dst := make([]byte, n)
	for i, bitOffset := 0, 0; i < n; i++ {
		byteIdx := bitOffset / 8
		bits := bitOffset % 8
		var v byte
		if byteIdx < len(src) {
			v = src[byteIdx] << bits
			if byteIdx+1 < len(src) {
				v |= src[byteIdx+1] >> (8 - bits)
			}
		}
		dst[i] = alphabet[v>>3]
		bitOffset += 5
	}
	return dst
}

// buildTunnelQuery builds a valid DNS TXT query with payload in EDNS option 0xFF00.
// Question name is minimal ("t" + domain). OPT advertises 4096-byte payload.
func buildTunnelQuery(payload []byte, domain dns.Name) (*dns.Message, error) {
	labels := append([][]byte{[]byte("t")}, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return nil, err
	}
	optData := dns.BuildEDNSOptions([]dns.EDNSOption{{Code: upstreamEDNSOptionCode, Data: payload}})
	return &dns.Message{
		ID:    0x1234,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: optData},
		},
	}, nil
}

// --- TestResponseFor ---

// TestResponseFor exercises the pure responseFor function with a variety of
// inputs to confirm it correctly validates and decodes incoming queries.
func TestResponseFor(t *testing.T) {
	domain, err := dns.ParseName("t.test.invalid")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}

	t.Run("valid query returns NoError and payload", func(t *testing.T) {
		// Build a minimal payload: 8-byte clientID + 1-byte padding header (0xe0 = 0 bytes pad) + no data.
		clientID := turbotunnel.NewClientID()
		rawPayload := append(clientID[:], 0xe0) // padding length prefix (224+0 = no padding bytes)

		query, err := buildTunnelQuery(rawPayload, domain)
		if err != nil {
			t.Fatalf("buildTunnelQuery: %v", err)
		}

		resp, payload, _ := responseFor(query, domain)
		if resp == nil {
			t.Fatal("responseFor returned nil response")
		}
		if resp.Rcode() != dns.RcodeNoError {
			t.Fatalf("expected RcodeNoError, got %d", resp.Rcode())
		}
		if len(payload) == 0 {
			t.Fatal("expected non-empty payload")
		}
		// First 8 bytes of payload should be the clientID.
		if !bytes.Equal(payload[:8], clientID[:]) {
			t.Errorf("payload prefix = %x, want %x", payload[:8], clientID[:])
		}
	})

	t.Run("response message (QR=1) returns nil", func(t *testing.T) {
		domain2, _ := dns.ParseName("other.test.invalid")
		query := &dns.Message{
			ID:    1,
			Flags: 0x8000, // QR=1 — this is a response, not a query
			Question: []dns.Question{
				{Name: domain2, Type: dns.RRTypeTXT, Class: dns.ClassIN},
			},
		}
		resp, _, _ := responseFor(query, domain)
		if resp != nil {
			t.Fatalf("expected nil for a DNS response message, got %+v", resp)
		}
	})

	t.Run("wrong domain returns NXDOMAIN", func(t *testing.T) {
		wrongDomain, _ := dns.ParseName("other.test.invalid")
		query := &dns.Message{
			ID:    2,
			Flags: 0x0100,
			Question: []dns.Question{
				{Name: wrongDomain, Type: dns.RRTypeTXT, Class: dns.ClassIN},
			},
			Additional: []dns.RR{
				{Type: dns.RRTypeOPT, Class: 4096, Data: []byte{}},
			},
		}
		resp, _, _ := responseFor(query, domain)
		if resp == nil {
			t.Fatal("expected non-nil response for wrong domain")
		}
		if resp.Rcode() != dns.RcodeNameError {
			t.Errorf("expected NXDOMAIN (3), got %d", resp.Rcode())
		}
	})

	t.Run("non-TXT QTYPE returns NXDOMAIN", func(t *testing.T) {
		query := &dns.Message{
			ID:    3,
			Flags: 0x0100,
			Question: []dns.Question{
				{Name: domain, Type: 1 /* A */, Class: dns.ClassIN},
			},
			Additional: []dns.RR{
				{Type: dns.RRTypeOPT, Class: 4096, Data: []byte{}},
			},
		}
		resp, _, _ := responseFor(query, domain)
		if resp == nil {
			t.Fatal("expected non-nil response for A query")
		}
		if resp.Rcode() != dns.RcodeNameError {
			t.Errorf("expected NXDOMAIN, got %d", resp.Rcode())
		}
	})

	t.Run("duplicate OPT RR returns FORMERR", func(t *testing.T) {
		query := &dns.Message{
			ID:    4,
			Flags: 0x0100,
			Question: []dns.Question{
				{Name: domain, Type: dns.RRTypeTXT, Class: dns.ClassIN},
			},
			Additional: []dns.RR{
				{Type: dns.RRTypeOPT, Class: 4096, Data: []byte{}},
				{Type: dns.RRTypeOPT, Class: 4096, Data: []byte{}},
			},
		}
		resp, _, _ := responseFor(query, domain)
		if resp == nil {
			t.Fatal("expected non-nil response for duplicate OPT")
		}
		if resp.Rcode() != dns.RcodeFormatError {
			t.Errorf("expected FORMERR (1), got %d", resp.Rcode())
		}
	})

	t.Run("EDNS payload 512 accepted (response capped, no FORMERR)", func(t *testing.T) {
		// Resolvers that only advertise 512 get accepted; server caps response size per request.
		clientID := turbotunnel.NewClientID()
		rawPayload := append(clientID[:], 0xe0)
		query, err := buildTunnelQuery(rawPayload, domain)
		if err != nil {
			t.Fatalf("buildTunnelQuery: %v", err)
		}
		query.Additional[0].Class = 512
		resp, payload, maxSize := responseFor(query, domain)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.Rcode() != dns.RcodeNoError {
			t.Errorf("expected NoError when EDNS=512 (cap response), got %d", resp.Rcode())
		}
		if len(payload) == 0 {
			t.Fatal("expected payload")
		}
		if maxSize != 512 {
			t.Errorf("maxResponseSize = %d, want 512", maxSize)
		}
	})

	t.Run("query without EDNS option 0xFF00 returns NXDOMAIN", func(t *testing.T) {
		// Valid subdomain but OPT has no our option (or payload too short).
		labels := append([][]byte{[]byte("t")}, domain...)
		name, _ := dns.NewName(labels)
		query := &dns.Message{
			ID:    5,
			Flags: 0x0100,
			Question: []dns.Question{
				{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
			},
			Additional: []dns.RR{
				{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
			},
		}
		resp, _, _ := responseFor(query, domain)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.Rcode() != dns.RcodeNameError {
			t.Errorf("expected NXDOMAIN when OPT has no 0xFF00, got %d", resp.Rcode())
		}
	})

	t.Run("name-based query (Base36 in name, no OPT payload) returns NoError and payload", func(t *testing.T) {
		// Simulates public resolvers: payload only in question name. Base36 (0-9a-v); server decodes case-insensitively.
		// Compact framing: poll = clientID(8) + 0 (9 bytes total).
		clientID := turbotunnel.NewClientID()
		rawPayload := append(clientID[:], 0) // compact poll: 8 + 1 byte
		enc := base36EncodeTest(rawPayload)
		var labels [][]byte
		for len(enc) > 0 {
			n := 63
			if n > len(enc) {
				n = len(enc)
			}
			labels = append(labels, enc[:n])
			enc = enc[n:]
		}
		labels = append(labels, domain...)
		name, err := dns.NewName(labels)
		if err != nil {
			t.Fatalf("NewName: %v", err)
		}
		query := &dns.Message{
			ID:    0x5678,
			Flags: 0x0100,
			Question: []dns.Question{
				{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
			},
			Additional: []dns.RR{
				{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
			},
		}
		resp, payload, _ := responseFor(query, domain)
		if resp == nil {
			t.Fatal("responseFor returned nil response")
		}
		if resp.Rcode() != dns.RcodeNoError {
			t.Fatalf("expected RcodeNoError for name-based query, got %d", resp.Rcode())
		}
		if !bytes.Equal(payload[:8], clientID[:]) {
			t.Errorf("payload prefix = %x, want %x", payload[:8], clientID[:])
		}
	})

	t.Run("name-based with lowercase subdomain (QNAME case randomization) still decodes", func(t *testing.T) {
		// Resolvers may lowercase or randomize case; server decodes Base36 case-insensitively.
		clientID := turbotunnel.NewClientID()
		rawPayload := append(clientID[:], 0xe0)
		enc := base36EncodeTest(rawPayload)
		enc = bytes.ToLower(enc) // simulate resolver sending lowercase
		var labels [][]byte
		for len(enc) > 0 {
			n := 63
			if n > len(enc) {
				n = len(enc)
			}
			labels = append(labels, enc[:n])
			enc = enc[n:]
		}
		labels = append(labels, domain...)
		name, _ := dns.NewName(labels)
		query := &dns.Message{
			ID:    0x9999,
			Flags: 0x0100,
			Question: []dns.Question{
				{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
			},
			Additional: []dns.RR{
				{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
			},
		}
		resp, payload, _ := responseFor(query, domain)
		if resp == nil || resp.Rcode() != dns.RcodeNoError {
			t.Fatalf("expected NoError when subdomain is lowercase (case randomization), got rcode %d", resp.Rcode())
		}
		if !bytes.Equal(payload[:8], clientID[:]) {
			t.Errorf("payload prefix = %x, want %x", payload[:8], clientID[:])
		}
	})
}

// --- TestRecvLoopInjectsPackets ---

// TestRecvLoopInjectsPackets sends a valid DNS tunnel query over a loopback UDP
// socket to a running recvLoop goroutine and verifies that the embedded KCP
// packet appears in the ttConn outgoing queue for the expected clientID.
func TestRecvLoopInjectsPackets(t *testing.T) {
	domain, err := dns.ParseName("t.test.invalid")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}

	// Set up a pair of loopback UDP sockets: dnsConn (server-side) and
	// clientConn (sends the crafted query).
	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dnsConn: %v", err)
	}
	defer dnsConn.Close()

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen clientConn: %v", err)
	}
	defer clientConn.Close()

	serverAddr := dnsConn.LocalAddr()

	// ttConn is the virtual PacketConn that recvLoop feeds with decoded packets.
	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 5*time.Minute)
	defer ttConn.Close()

	// ch receives record structs from recvLoop → sendLoop. We don't run
	// sendLoop, so use a buffered channel to prevent recvLoop from blocking.
	ch := make(chan *record, 64)

	// Start recvLoop in a goroutine. It returns when dnsConn is closed.
	done := make(chan error, 1)
	go func() {
		done <- recvLoop(domain, dnsConn, ttConn, ch, nil)
	}()

	// Build a query that carries a real KCP-style packet.
	// Packet format inside the name (after base36+domain):
	//   [clientID:8][padding header 0xe3][3 random pad bytes][packet len 0x04][4 data bytes]
	clientID := turbotunnel.NewClientID()
	dataPacket := []byte{0xde, 0xad, 0xbe, 0xef}

	var payloadBuf bytes.Buffer
	payloadBuf.Write(clientID[:])
	// padding: 0xe0+3 = padding of 3 bytes
	payloadBuf.WriteByte(0xe0 + 3)
	payloadBuf.Write([]byte{0x00, 0x00, 0x00}) // 3 padding bytes
	// data packet: length prefix then data
	payloadBuf.WriteByte(byte(len(dataPacket)))
	payloadBuf.Write(dataPacket)

	query, err := buildTunnelQuery(payloadBuf.Bytes(), domain)
	if err != nil {
		t.Fatalf("buildTunnelQuery: %v", err)
	}

	// Serialize the DNS query to wire format.
	wireQuery, err := query.WireFormat()
	if err != nil {
		t.Fatalf("WireFormat: %v", err)
	}

	// Send the query UDP packet to the server.
	_, err = clientConn.WriteTo(wireQuery, serverAddr)
	if err != nil {
		t.Fatalf("WriteTo server: %v", err)
	}

	// recvLoop calls ttConn.QueueIncoming(p, clientID), which puts decoded
	// packets into ttConn's *incoming* queue (returned by ReadFrom).
	// Read from ttConn in a goroutine with a timeout.
	type readResult struct {
		data    []byte
		srcAddr net.Addr
		err     error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := ttConn.ReadFrom(buf)
		readDone <- readResult{buf[:n], addr, err}
	}()

	select {
	case res := <-readDone:
		if res.err != nil {
			t.Fatalf("ttConn.ReadFrom: %v", res.err)
		}
		if !bytes.Equal(res.data, dataPacket) {
			t.Errorf("got packet %x, want %x", res.data, dataPacket)
		}
		if res.srcAddr != clientID {
			t.Errorf("srcAddr = %v, want clientID %v", res.srcAddr, clientID)
		}
		t.Logf("recvLoop correctly injected packet %x for clientID %s", res.data, clientID)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for packet to appear in ttConn incoming queue")
	}

	// Verify that recvLoop also queued a response record (the partial DNS response).
	select {
	case rec := <-ch:
		if rec == nil {
			t.Fatal("received nil record from ch")
		}
		if rec.ClientID != clientID {
			t.Errorf("record.ClientID = %s, want %s", rec.ClientID, clientID)
		}
		if rec.Resp == nil {
			t.Fatal("record.Resp is nil")
		}
		if rec.Resp.Rcode() != dns.RcodeNoError {
			t.Errorf("record.Resp.Rcode = %d, want 0 (NoError)", rec.Resp.Rcode())
		}
		t.Logf("recvLoop queued response record for clientID %s, rcode=%d", rec.ClientID, rec.Resp.Rcode())
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for response record in ch")
	}

	// Close the server socket to stop recvLoop.
	dnsConn.Close()
	select {
	case err := <-done:
		if err != nil && !isClosedError(err) {
			t.Errorf("recvLoop returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("recvLoop did not exit after dnsConn.Close()")
	}
}

// isClosedError returns true if err indicates a closed network connection,
// which is expected when dnsConn is closed while recvLoop is blocked on ReadFrom.
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "closed") || contains(s, "use of closed network connection")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
