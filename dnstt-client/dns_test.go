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
	conn := NewDNSPacketConn(pconn, pconn.LocalAddr(), domain)
	defer conn.Close()
	p1 := conn.buildUpstreamPayload(nil)
	p2 := conn.buildUpstreamPayload(nil)
	if bytes.Equal(p1, p2) {
		t.Error("buildUpstreamPayload(nil) returned identical payloads twice; poll should include random noise")
	}
	// Poll payload must be clientID(8) + 0 + noise(6) = at least 15 bytes
	if len(p1) < 9+probeNoiseLen || len(p2) < 9+probeNoiseLen {
		t.Errorf("poll payload too short: %d, %d (want >= %d)", len(p1), len(p2), 9+probeNoiseLen)
	}
}
