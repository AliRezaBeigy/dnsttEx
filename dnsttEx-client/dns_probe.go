// DNS probe messages (PING/PONG) and MTU discovery for the client.
// See dns.go for DNSPacketConn and encoding.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"
)

// probeNoiseLen is the number of random bytes appended to each PING to avoid
// DNS/resolver cache (query name changes every time).
const probeNoiseLen = 6

// BuildProbeMessage builds a minimal DNS message for health check: client sends
// PING (mode 0xFF), server responds with PONG. Used by the health checker and -scan.
func BuildProbeMessage(domain dns.Name, clientID turbotunnel.ClientID) ([]byte, error) {
	raw := make([]byte, 9+probeNoiseLen)
	copy(raw, clientID[:])
	raw[8] = probeModePING
	if _, err := rand.Read(raw[9:]); err != nil {
		return nil, err
	}
	encoded := make([]byte, base36EncodedLen(len(raw)))
	base36Encode(encoded, raw)
	labels := chunks(encoded, maxLabelLen)
	labels = append(labels, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return nil, err
	}
	var id uint16
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		return nil, err
	}
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
		},
	}
	return query.WireFormat()
}

// BuildMTUProbeMessage builds a PING probe that asks the server to respond with a payload of
// responseSize bytes (for MTU discovery). OPT Class in the query is set to responseSize.
func BuildMTUProbeMessage(domain dns.Name, clientID turbotunnel.ClientID, responseSize int) ([]byte, error) {
	if responseSize < 0 || responseSize > 65535 {
		responseSize = 512
	}
	raw := make([]byte, 9+2+probeNoiseLen)
	copy(raw, clientID[:])
	raw[8] = probeModePING
	raw[9] = byte(responseSize >> 8)
	raw[10] = byte(responseSize)
	if _, err := rand.Read(raw[11:]); err != nil {
		return nil, err
	}
	encoded := make([]byte, base36EncodedLen(len(raw)))
	base36Encode(encoded, raw)
	labels := chunks(encoded, maxLabelLen)
	labels = append(labels, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return nil, err
	}
	optClass := uint16(responseSize)
	if optClass < 512 {
		optClass = 512
	}
	var id uint16
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		return nil, err
	}
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: optClass, TTL: 0, Data: []byte{}},
		},
	}
	return query.WireFormat()
}

// VerifyMTUProbeResponse checks that we received a valid PONG and the response size
// is at least the requested size (with small tolerance for DNS TXT encoding).
func VerifyMTUProbeResponse(buf []byte, domain dns.Name, responseSize int) bool {
	tolerance := 16
	if responseSize/255 > tolerance {
		tolerance = responseSize / 255
	}
	if len(buf) < responseSize-tolerance {
		return false
	}
	resp, err := dns.MessageFromWireFormat(buf)
	if err != nil {
		return false
	}
	payload := dnsResponsePayload(&resp, domain)
	return payload != nil
}

const maxProbeQNameSize = 255

// probeRequestQNameLen returns the question QNAME wire length for a PING probe
// with the given raw payload length.
func probeRequestQNameLen(domain dns.Name, rawLen int) (int, error) {
	if rawLen <= 0 {
		return 0, fmt.Errorf("rawLen must be positive")
	}
	dummy := make([]byte, rawLen)
	encoded := make([]byte, base36EncodedLen(len(dummy)))
	base36Encode(encoded, dummy)
	labels := chunks(encoded, maxLabelLen)
	labels = append(labels, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return 0, err
	}
	qnl := 0
	for _, lab := range name {
		qnl += 1 + len(lab)
	}
	qnl++
	if qnl > maxProbeQNameSize {
		return 0, fmt.Errorf("QNAME would exceed %d octets", maxProbeQNameSize)
	}
	return qnl, nil
}

// BuildProbeMessageWithRequestSize builds a PING probe whose question QNAME wire
// length is at least minQNameSize (client MTU discovery).
func BuildProbeMessageWithRequestSize(domain dns.Name, clientID turbotunnel.ClientID, minQNameSize int) ([]byte, error) {
	if minQNameSize > maxProbeQNameSize {
		return nil, fmt.Errorf("minQNameSize %d exceeds max QNAME %d", minQNameSize, maxProbeQNameSize)
	}
	if minQNameSize < 1 {
		return nil, fmt.Errorf("minQNameSize must be positive")
	}
	baseLen := 9 + probeNoiseLen
	lo, hi := baseLen, 256
	for lo+1 < hi {
		mid := (lo + hi) / 2
		qnl, err := probeRequestQNameLen(domain, mid)
		if err != nil {
			hi = mid
			continue
		}
		if qnl >= minQNameSize {
			hi = mid
		} else {
			lo = mid
		}
	}
	padLen := hi - baseLen
	raw := make([]byte, baseLen+padLen)
	copy(raw, clientID[:])
	raw[8] = probeModePING
	if _, err := rand.Read(raw[9:]); err != nil {
		return nil, err
	}
	encoded := make([]byte, base36EncodedLen(len(raw)))
	base36Encode(encoded, raw)
	labels := chunks(encoded, maxLabelLen)
	labels = append(labels, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return nil, err
	}
	var id uint16
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		return nil, err
	}
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
		},
	}
	return query.WireFormat()
}

// ProbeResponsePONG is the exact payload the server must return for a PING health check.
var ProbeResponsePONG = []byte("PONG")

// VerifyProbeResponse checks that a raw DNS wire-format response is a valid PONG.
func VerifyProbeResponse(buf []byte, domain dns.Name) bool {
	return ExplainProbeResponseFailure(buf, domain) == ""
}

// ExplainProbeResponseFailure returns why a response is not a valid PONG; empty string means valid.
func ExplainProbeResponseFailure(buf []byte, domain dns.Name) string {
	resp, err := dns.MessageFromWireFormat(buf)
	if err != nil {
		return "parse error: " + err.Error()
	}
	if resp.Flags&0x8000 == 0 {
		return "not a response (QR=0)"
	}
	rcode := resp.Flags & 0x000f
	if rcode != dns.RcodeNoError {
		return fmt.Sprintf("rcode %d (expected no error)", rcode)
	}
	if len(resp.Question) != 1 {
		return "wrong number of questions"
	}
	if _, ok := resp.Question[0].Name.TrimSuffix(domain); !ok {
		return "question name not under domain"
	}
	payload := dnsResponsePayload(&resp, domain)
	if payload == nil {
		return "no TXT answer or EDNS payload under domain"
	}
	if !bytes.Equal(payload, ProbeResponsePONG) {
		return fmt.Sprintf("payload len %d (expected PONG); resolver may be forwarding to wrong server", len(payload))
	}
	return ""
}
