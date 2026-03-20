package main

import (
	"bytes"
	"io"
	"net"
	"testing"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"
)

func allPackets(buf []byte) ([][]byte, error) {
	var packets [][]byte
	r := bytes.NewReader(buf)
	for {
		p, err := nextPacket(r)
		if err != nil {
			return packets, err
		}
		packets = append(packets, p)
	}
}

func packetsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func TestNextPacket(t *testing.T) {
	for _, test := range []struct {
		input   string
		packets [][]byte
		err     error
	}{
		{"", [][]byte{}, io.EOF},
		{"\x00", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x00", [][]byte{{}}, io.EOF},
		{"\x00\x00\x00", [][]byte{{}}, io.ErrUnexpectedEOF},
		{"\x00\x01", [][]byte{}, io.ErrUnexpectedEOF},
		{"\x00\x05hello\x00\x05world", [][]byte{[]byte("hello"), []byte("world")}, io.EOF},
	} {
		packets, err := allPackets([]byte(test.input))
		if !packetsEqual(packets, test.packets) || err != test.err {
			t.Errorf("%x\nreturned %x %v\nexpected %x %v",
				test.input, packets, err, test.packets, test.err)
		}
	}
}

// TestBuildProbeMessageUnique verifies that each call to BuildProbeMessage
// produces a different wire encoding (noise avoids DNS cache).
func TestBuildProbeMessageUnique(t *testing.T) {
	domain, err := dns.ParseName("health.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	var clientID turbotunnel.ClientID
	for i := range clientID {
		clientID[i] = byte(i)
	}
	wire1, err := BuildProbeMessage(domain, clientID)
	if err != nil {
		t.Fatalf("BuildProbeMessage: %v", err)
	}
	wire2, err := BuildProbeMessage(domain, clientID)
	if err != nil {
		t.Fatalf("BuildProbeMessage: %v", err)
	}
	if bytes.Equal(wire1, wire2) {
		t.Error("BuildProbeMessage returned identical wire bytes twice; probe should include random noise")
	}
}

// TestVerifyProbeResponse verifies that VerifyProbeResponse accepts a valid
// PONG response and rejects wrong payload or rcode.
func TestVerifyProbeResponse(t *testing.T) {
	domain, err := dns.ParseName("health.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	// Build a valid PONG response: QR=1, RcodeNoError, one Question (name under domain), one Answer TXT with "PONG".
	resp := &dns.Message{
		ID:    12345,
		Flags: 0x8000 | dns.RcodeNoError, // QR + NoError
		Question: []dns.Question{
			{Name: domain, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		Answer: []dns.RR{
			{Name: domain, Type: dns.RRTypeTXT, Class: dns.ClassIN, TTL: 0, Data: dns.EncodeRDataTXT([]byte("PONG"))},
		},
	}
	wire, err := resp.WireFormat()
	if err != nil {
		t.Fatalf("WireFormat: %v", err)
	}
	if !VerifyProbeResponse(wire, domain) {
		t.Error("VerifyProbeResponse rejected valid PONG response")
	}
	// Wrong payload: "WRONG" instead of "PONG"
	resp.Answer[0].Data = dns.EncodeRDataTXT([]byte("WRONG"))
	wire, _ = resp.WireFormat()
	if VerifyProbeResponse(wire, domain) {
		t.Error("VerifyProbeResponse accepted wrong payload")
	}
	// Wrong rcode: NXDOMAIN
	resp.Answer[0].Data = dns.EncodeRDataTXT([]byte("PONG"))
	resp.Flags = 0x8000 | dns.RcodeNameError
	wire, _ = resp.WireFormat()
	if VerifyProbeResponse(wire, domain) {
		t.Error("VerifyProbeResponse accepted NXDOMAIN response")
	}
}

// TestPollPayloadNoise verifies that buildUpstreamPayload(nil) produces different
// payloads each time (noise avoids DNS cache for idle polls).
func TestPollPayloadNoise(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()
	domain, err := dns.ParseName("poll.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	conn := NewDNSPacketConn(pconn, pconn.LocalAddr(), domain, 0, 0)
	defer conn.Close()
	p1 := conn.buildUpstreamPayload(nil, 0)
	p2 := conn.buildUpstreamPayload(nil, 0)
	if bytes.Equal(p1, p2) {
		t.Error("buildUpstreamPayload(nil,0) returned identical payloads twice; poll should include random noise")
	}
	// v2 poll: clientID(8) + marker(1) + hint(2) + poll(1) + noise(6) = at least 18 bytes
	if len(p1) < 12+probeNoiseLen || len(p2) < 12+probeNoiseLen {
		t.Errorf("poll payload too short: %d, %d (want >= %d)", len(p1), len(p2), 12+probeNoiseLen)
	}
	// With explicit hint: same v2 layout, but hint bytes must match.
	h1 := conn.buildUpstreamPayload(nil, 512)
	if len(h1) < 12+probeNoiseLen {
		t.Errorf("hint-poll payload too short: %d (want >= %d)", len(h1), 12+probeNoiseLen)
	}
	if h1[8] != probeModeSizedFrame {
		t.Errorf("framing marker byte = 0x%02x, want 0x%02x", h1[8], probeModeSizedFrame)
	}
	if h1[11] != probeModePoll {
		t.Errorf("poll frame byte = 0x%02x, want 0x%02x", h1[11], probeModePoll)
	}
	gotHint := int(h1[9])<<8 | int(h1[10])
	if gotHint != 512 {
		t.Errorf("hint-poll response hint = %d, want 512", gotHint)
	}
}

// TestEffectiveSendCapacityRespectsMTU verifies that when maxRequestSize is set (QNAME limit),
// effectiveSendCapacity caps payload so the question QNAME does not exceed it.
func TestEffectiveSendCapacityRespectsMTU(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()
	domain, err := dns.ParseName("mtu.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	maxQName := 120
	conn := NewDNSPacketConn(pconn, pconn.LocalAddr(), domain, 4096, maxQName)
	defer conn.Close()

	capacity := conn.effectiveSendCapacity()
	if capacity <= 0 {
		t.Fatalf("effectiveSendCapacity() = %d, want > 0", capacity)
	}
	decoded := make([]byte, capacity)
	decoded[0] = 0
	wire, err := conn.buildQueryWire(decoded, 0)
	if err != nil {
		t.Fatalf("buildQueryWire: %v", err)
	}
	qnl, ok := dnsQuestionQNameWireLen(wire)
	if !ok {
		t.Fatal("no QNAME in wire")
	}
	if qnl > maxQName {
		t.Errorf("QNAME length %d exceeds maxQName %d (capacity used %d)", qnl, maxQName, capacity)
	}
}

// TestKCPMTUHintMatchesUpstreamFraming ensures a full-MSS segment from KCP still
// fits in effectiveSendCapacity after buildUpstreamPayload's single-packet encoding.
// If hint is too large, send() stashes every segment and sendLoop spins on poll+unstash.
func TestKCPMTUHintMatchesUpstreamFraming(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()
	domain, err := dns.ParseName("hint.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	conn := NewDNSPacketConn(pconn, pconn.LocalAddr(), domain, 4096, 120)
	defer conn.Close()

	cap := conn.effectiveSendCapacity()
	hint := conn.KCPMTUHint()
	if hint < 1 {
		t.Fatalf("KCPMTUHint() = %d, want >= 1 for this test domain", hint)
	}
	seg := make([]byte, hint)
	for i := range seg {
		seg[i] = byte(i)
	}
	decoded := conn.buildUpstreamPayload([][]byte{seg}, 512)
	if len(decoded) > cap {
		t.Fatalf("buildUpstreamPayload(max segment) len %d > effectiveSendCapacity %d (hint=%d)", len(decoded), cap, hint)
	}
}

// TestBuildQueryWireUsesOptMaxResp verifies that buildQueryWire(decoded, optMaxResp)
// sets the OPT RR Class (max response size) to optMaxResp when optMaxResp > 0.
func TestBuildQueryWireUsesOptMaxResp(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()
	domain, err := dns.ParseName("opt.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	conn := NewDNSPacketConn(pconn, pconn.LocalAddr(), domain, 0, 0)
	defer conn.Close()

	decoded := conn.buildUpstreamPayload(nil, 0)
	for _, wantClass := range []int{512, 1024, 2048, 4096} {
		wire, err := conn.buildQueryWire(decoded, wantClass)
		if err != nil {
			t.Fatalf("buildQueryWire(_, %d): %v", wantClass, err)
		}
		msg, err := dns.MessageFromWireFormat(wire)
		if err != nil {
			t.Fatalf("MessageFromWireFormat: %v", err)
		}
		var optClass uint16
		for _, rr := range msg.Additional {
			if rr.Type == dns.RRTypeOPT {
				optClass = rr.Class
				break
			}
		}
		if optClass != uint16(wantClass) {
			t.Errorf("OPT Class = %d, want %d", optClass, wantClass)
		}
	}
}

// TestBuildProbeMessageWithRequestSizeMinPadding verifies that we add the minimum
// padding needed to reach minRequestSize (no arbitrary 48-byte chunks that overshoot).
func TestBuildProbeMessageWithRequestSizeMinPadding(t *testing.T) {
	domain, err := dns.ParseName("mtu.test.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	var clientID turbotunnel.ClientID
	for i := range clientID {
		clientID[i] = byte(i)
	}
	for _, minQName := range []int{64, 128, 192} {
		wire, err := BuildProbeMessageWithRequestSize(domain, clientID, minQName)
		if err != nil {
			t.Fatalf("BuildProbeMessageWithRequestSize(_, _, %d): %v", minQName, err)
		}
		msg, err := dns.MessageFromWireFormat(wire)
		if err != nil || len(msg.Question) != 1 {
			t.Fatalf("parse probe: %v", err)
		}
		qnl := 0
		for _, lab := range msg.Question[0].Name {
			qnl += 1 + len(lab)
		}
		qnl++ // root
		if qnl < minQName {
			t.Errorf("minQName %d: QNAME length %d < minQName", minQName, qnl)
		}
		if qnl > minQName+20 {
			t.Errorf("minQName %d: QNAME length %d (expected minimal padding)", minQName, qnl)
		}
	}
}

func TestIsExplicitEmptyMarker(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    bool
	}{
		{name: "nil", payload: nil, want: false},
		{name: "empty", payload: []byte{}, want: false},
		{name: "single zero", payload: []byte{0x00}, want: true},
		{name: "single non-zero", payload: []byte{0x01}, want: false},
		{name: "two bytes starts zero", payload: []byte{0x00, 0x00}, want: false},
	}
	for _, tc := range tests {
		if got := isExplicitEmptyMarker(tc.payload); got != tc.want {
			t.Errorf("%s: isExplicitEmptyMarker(%x) = %v, want %v", tc.name, tc.payload, got, tc.want)
		}
	}
}
