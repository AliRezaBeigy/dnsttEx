package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"
)

// EDNS option codes (used when resolver forwards them; name-based is fallback for 8.8.8.8 etc).
const (
	upstreamEDNSOptionCode   = 0xFF00
	downstreamEDNSOptionCode = 0xFF01
)

const (
	numPadding        = 0
	numPaddingForPoll = 8

	initPollDelay       = 50 * time.Millisecond
	maxPollDelay        = 500 * time.Millisecond
	pollDelayMultiplier = 2.0
	pollLimit           = 16

	maxPacketSize = 223 // max packet size (1-byte length prefix)

	// RFC 1035 max is 63; 57 leaves more room in 253-octet name.
	maxLabelLen = 57
	// Consecutive send errors before we back off poll rate (resolver rate limiting).
	rateLimitBackoffThreshold  = 3
	rateLimitBackoffMultiplier = 2.0
)

// Base36 uses 0-9a-v (32 of 36 symbols); 5 bits/symbol so expansion = 8/5, same as Base32.
// Server decodes case-insensitively for QNAME randomization. Alphabet is DNS-safe.
const base36Alphabet = "0123456789abcdefghijklmnopqrstuv"

func base36EncodedLen(n int) int { return (n*8 + 4) / 5 }

func base36Encode(dst, src []byte) {
	for i, bitOffset := 0, 0; i < len(dst); i++ {
		byteIdx := bitOffset / 8
		bits := bitOffset % 8
		var v byte
		if byteIdx < len(src) {
			v = src[byteIdx] << bits
			if byteIdx+1 < len(src) {
				v |= src[byteIdx+1] >> (8 - bits)
			}
		}
		dst[i] = base36Alphabet[v>>3]
		bitOffset += 5
	}
}

var errBase36Decode = errors.New("invalid base36")

func base36Decode(dst, src []byte) error {
	bits := 0
	acc := uint(0)
	out := 0
	for _, c := range src {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'z':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'Z':
			v = c - 'A' + 10
		default:
			return errBase36Decode
		}
		if v >= 32 {
			return errBase36Decode
		}
		acc = acc<<5 | uint(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if out < len(dst) {
				dst[out] = byte(acc >> bits)
			}
			out++
		}
	}
	return nil
}

func base36DecodedLen(n int) int { return n * 5 / 8 }

// DNSPacketConn sends and receives tunnel payload over DNS. Upstream is Base36 in the
// question name (0-9a-v); server decodes case-insensitively for QNAME randomization.
// No EDNS for payload. Downstream from TXT Answer first, then EDNS 0xFF01 if present.
//
// We don't have a need to match up a query and a response by ID. Queries and
// responses are vehicles for carrying data and for our purposes don't need to
// be correlated. When sending a query, we generate a random ID, and when
// receiving a response, we ignore the ID.
type DNSPacketConn struct {
	clientID        turbotunnel.ClientID
	domain          dns.Name
	maxResponseSize int // max UDP response size to request (OPT Class); 0 = 4096
	// Sending on pollChan permits sendLoop to send an empty polling query.
	// sendLoop also does its own polling according to a time schedule.
	pollChan chan struct{}
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// NewDNSPacketConn creates a new DNSPacketConn. transport, through its WriteTo
// and ReadFrom methods, handles the actual sending and receiving the DNS
// messages encoded by DNSPacketConn. addr is the address to be passed to
// transport.WriteTo whenever a message needs to be sent. maxResponseSize is the
// max response size to request from the server (OPT Class); 0 means 4096.
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, maxResponseSize int) *DNSPacketConn {
	// Generate a new random ClientID.
	clientID := turbotunnel.NewClientID()
	c := &DNSPacketConn{
		clientID:        clientID,
		domain:          domain,
		maxResponseSize: maxResponseSize,
		pollChan:        make(chan struct{}, pollLimit),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go func() {
		err := c.recvLoop(transport)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
	}()
	go func() {
		err := c.sendLoop(transport, addr)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()
	return c
}

// dnsResponsePayload extracts downstream payload. Prefers TXT Answer (works with
// all resolvers); falls back to EDNS option 0xFF01 if present.
func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 || resp.Flags&0x000f != dns.RcodeNoError {
		return nil
	}
	if len(resp.Question) != 1 {
		return nil
	}
	if _, ok := resp.Question[0].Name.TrimSuffix(domain); !ok {
		return nil
	}
	// Prefer TXT Answer so 8.8.8.8 and other public resolvers work (they don't strip TXT).
	if len(resp.Answer) == 1 {
		answer := resp.Answer[0]
		if _, ok := answer.Name.TrimSuffix(domain); ok && answer.Type == dns.RRTypeTXT {
			if p, err := dns.DecodeRDataTXT(answer.Data); err == nil {
				return p
			}
		}
	}
	// Fallback: EDNS option (when resolver forwards it).
	for _, rr := range resp.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		opts, err := dns.ParseEDNSOptions(rr.Data)
		if err != nil {
			continue
		}
		if data := dns.FindEDNSOption(opts, downstreamEDNSOptionCode); data != nil {
			return data
		}
	}
	return nil
}

// nextPacket reads the next length-prefixed packet from r. It returns a nil
// error only when a complete packet was read. It returns io.EOF only when there
// were 0 bytes remaining to read from r. It returns io.ErrUnexpectedEOF when
// EOF occurs in the middle of an encoded packet.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	for {
		var n uint16
		err := binary.Read(r, binary.BigEndian, &n)
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		p := make([]byte, n)
		_, err = io.ReadFull(r, p)
		// Here we must change io.EOF to io.ErrUnexpectedEOF.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return p, err
	}
}

// recvLoop repeatedly calls transport.ReadFrom to receive a DNS message,
// extracts its payload and breaks it into packets, and stores the packets in a
// queue to be returned from a future call to c.ReadFrom.
//
// Whenever we receive a DNS response containing at least one data packet, we
// send on c.pollChan to permit sendLoop to send an immediate polling queries.
// KCP itself will also send an ACK packet for incoming data, which is
// effectively a second poll. Therefore, each time we receive data, we send up
// to 2 polling queries (or 1 + f polling queries, if KCP only ACKs an f
// fraction of incoming data). We say "up to" because sendLoop will discard an
// empty polling query if it has an organic non-empty packet to send (this goes
// also for KCP's organic ACK packets).
//
// The intuition behind polling immediately after receiving is that if server
// has just had something to send, it may have more to send, and in order for
// the server to send anything, we must give it a query to respond to. The
// intuition behind polling *2 times* (or 1 + f times) is similar to TCP slow
// start: we want to maintain some number of queries "in flight", and the faster
// the server is sending, the higher that number should be. If we polled only
// once for each received packet, we would tend to have only one query in flight
// at a time, ping-pong style. The first polling query replaces the in-flight
// query that has just finished its duty in returning data to us; the second
// grows the effective in-flight window proportional to the rate at which
// data-carrying responses are being received. Compare to Eq. (2) of
// https://tools.ietf.org/html/rfc5681#section-3.1. The differences are that we
// count messages, not bytes, and we don't maintain an explicit window. If a
// response comes back without data, or if a query or response is dropped by the
// network, then we don't poll again, which decreases the effective in-flight
// window.
func (c *DNSPacketConn) recvLoop(transport net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		// Got a response. Try to parse it as a DNS message.
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("MessageFromWireFormat: %v", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		any := false
		nPackets := 0
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			nPackets++
			c.QueuePacketConn.QueueIncoming(p, addr)
		}
		if os.Getenv("DNSTT_DEBUG") != "" && len(payload) > 0 {
			log.Printf("[client] received payload %d bytes (%d packets)", len(payload), nPackets)
		}

		// If the payload contained one or more packets, permit sendLoop
		// to poll immediately. ACKs on received data will effectively
		// serve as another stream of polls whose rate is proportional
		// to the rate of incoming packets.
		if any {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

func nameCapacity(domain dns.Name) int {
	capacity := 255 - 1
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * maxLabelLen / (maxLabelLen + 1) // each label: 1 byte length + maxLabelLen
	capacity = capacity * 5 / 8                           // Base36 expansion (5 bits/symbol, same as Base32)
	return capacity
}

func chunks(p []byte, n int) [][]byte {
	var out [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		out = append(out, p[:sz])
		p = p[sz:]
	}
	return out
}

// buildUpstreamPayload builds raw payload with compact framing:
//   - ClientID(8) + mode byte. Mode: 0 = poll (no data); 1–223 = single packet of that length; 224+ = legacy (224+nPad, nPad bytes, then [1-byte len + packet]*).
//   For poll (no data), random bytes are appended so each query name differs (avoids DNS/resolver cache).
func (c *DNSPacketConn) buildUpstreamPayload(packets [][]byte) []byte {
	var buf bytes.Buffer
	buf.Write(c.clientID[:])
	if len(packets) == 0 {
		buf.WriteByte(0) // poll: no data
		noise := make([]byte, probeNoiseLen)
		if _, err := rand.Read(noise); err == nil {
			buf.Write(noise)
		}
		return buf.Bytes()
	}
	if len(packets) == 1 && len(packets[0]) >= 1 && len(packets[0]) < 224 {
		buf.WriteByte(byte(len(packets[0])))
		buf.Write(packets[0])
		return buf.Bytes()
	}
	// Legacy multi-packet or single packet with len 0 or >= 224
	nPad := numPadding
	buf.WriteByte(byte(224 + nPad))
	io.CopyN(&buf, rand.Reader, int64(nPad))
	for _, p := range packets {
		if len(p) >= 224 {
			continue
		}
		buf.WriteByte(byte(len(p)))
		buf.Write(p)
	}
	return buf.Bytes()
}

// send encodes payload in the question name (Base36, 0-9a-v) for public resolvers; no EDNS.
func (c *DNSPacketConn) send(transport net.PacketConn, packets [][]byte, addr net.Addr) error {
	capacity := nameCapacity(c.domain)
	decoded := c.buildUpstreamPayload(packets)
	for len(decoded) > capacity && len(packets) > 1 {
		// Stash last packet and try again with fewer.
		c.QueuePacketConn.Stash(packets[len(packets)-1], addr)
		packets = packets[:len(packets)-1]
		decoded = c.buildUpstreamPayload(packets)
	}
	if len(decoded) > capacity && len(packets) == 1 {
		c.QueuePacketConn.Stash(packets[0], addr)
		decoded = c.buildUpstreamPayload(nil)
	}
	encoded := make([]byte, base36EncodedLen(len(decoded)))
	base36Encode(encoded, decoded)
	// Server decodes case-insensitively for QNAME randomization
	labels := chunks(encoded, maxLabelLen)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}
	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	optClass := uint16(4096)
	if c.maxResponseSize > 0 {
		optClass = uint16(c.maxResponseSize)
		if optClass < 512 {
			optClass = 512
		}
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
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}
	if os.Getenv("DNSTT_DEBUG") != "" {
		if len(packets) > 0 {
			log.Printf("[client] send name payload %d bytes (%d packets)", len(decoded), len(packets))
		}
		hexLen := 64
		if len(buf) < hexLen {
			hexLen = len(buf)
		}
		log.Printf("[client] send to %s wire=%d id=%d hex=%s", addr, len(buf), query.ID, hex.EncodeToString(buf[:hexLen]))
	}
	_, err = transport.WriteTo(buf, addr)
	return err
}

// Probe mode bytes (first byte of payload after clientID).
const (
	probeModePoll = 0   // normal idle poll
	probeModePING = 0xFF // health-check PING; server must respond with PONG
)

// probeNoiseLen is the number of random bytes appended to each PING to avoid
// DNS/resolver cache (query name changes every time).
const probeNoiseLen = 6

// BuildProbeMessage builds a minimal DNS message for health check: client sends
// PING (mode 0xFF), server responds with PONG. Used by the health checker and -scan.
// Random bytes are appended after PING so each probe has a unique query name (cache bust).
func BuildProbeMessage(domain dns.Name, clientID turbotunnel.ClientID) ([]byte, error) {
	// Payload: clientID(8) + mode byte PING + random noise (cache bust).
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
	binary.Read(rand.Reader, binary.BigEndian, &id)
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
// responseSize bytes (for MTU discovery). Payload: clientID(8) + PING(1) + size_hi(1) + size_lo(1) + noise.
// OPT Class in the query is set to responseSize so the server caps the response.
func BuildMTUProbeMessage(domain dns.Name, clientID turbotunnel.ClientID, responseSize int) ([]byte, error) {
	if responseSize < 0 || responseSize > 65535 {
		responseSize = 512
	}
	// Payload: clientID(8) + PING(1) + size_hi(1) + size_lo(1) + noise
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
	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	optClass := uint16(responseSize)
	if optClass < 512 {
		optClass = 512 // RFC 6891
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
// is at least the requested size (allowing small tolerance for DNS TXT encoding).
// The server sizes MTU-probe responses to the requested size so we can verify the
// path delivered that many bytes; significantly less may indicate truncation or
// broken DNS and must not be accepted as MTU success.
func VerifyMTUProbeResponse(buf []byte, domain dns.Name, responseSize int) bool {
	// Allow tolerance for TXT chunking (1 byte per 255 payload bytes); reject clear truncation.
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

// BuildProbeMessageWithRequestSize builds a PING probe whose wire size is at least minRequestSize
// bytes (for client MTU discovery). Padding is added in the question name until the packet is large enough.
func BuildProbeMessageWithRequestSize(domain dns.Name, clientID turbotunnel.ClientID, minRequestSize int) ([]byte, error) {
	raw := make([]byte, 9+probeNoiseLen)
	copy(raw, clientID[:])
	raw[8] = probeModePING
	if _, err := rand.Read(raw[9:]); err != nil {
		return nil, err
	}
	for {
		encoded := make([]byte, base36EncodedLen(len(raw)))
		base36Encode(encoded, raw)
		labels := chunks(encoded, maxLabelLen)
		labels = append(labels, domain...)
		name, err := dns.NewName(labels)
		if err != nil {
			return nil, err
		}
		query := &dns.Message{
			ID:    0,
			Flags: 0x0100,
			Question: []dns.Question{
				{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
			},
			Additional: []dns.RR{
				{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
			},
		}
		wire, err := query.WireFormat()
		if err != nil {
			return nil, err
		}
		if len(wire) >= minRequestSize {
			binary.Read(rand.Reader, binary.BigEndian, &query.ID)
			return query.WireFormat()
		}
		// Add padding (about 40 raw bytes → ~64 encoded → ~70 wire bytes per iteration)
		extra := make([]byte, 48)
		rand.Read(extra)
		raw = append(raw, extra...)
	}
}

// ProbeResponsePONG is the exact payload the server must return for a PING health check.
var ProbeResponsePONG = []byte("PONG")

// VerifyProbeResponse checks that a raw DNS wire-format response is a valid
// PONG to our PING: RcodeNoError, question under domain, and payload equals "PONG".
func VerifyProbeResponse(buf []byte, domain dns.Name) bool {
	return ExplainProbeResponseFailure(buf, domain) == ""
}

// ExplainProbeResponseFailure returns why a response is not a valid PONG; empty string means valid.
// Used by -scan to log why a resolver was rejected (e.g. "payload len 1155, expected PONG").
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

// sendLoop batches packets into the question name (limited by nameCapacity). Also sends polling queries when idle.
// Poll timing can be overridden with DNSTT_POLL_INIT_MS and DNSTT_POLL_MAX_MS (e.g. 500/2000 for conservative resolvers).
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) error {
	initPoll, maxPoll := initPollDelay, maxPollDelay
	if s := os.Getenv("DNSTT_POLL_INIT_MS"); s != "" {
		if ms, err := strconv.Atoi(s); err == nil && ms > 0 {
			initPoll = time.Duration(ms) * time.Millisecond
		}
	}
	if s := os.Getenv("DNSTT_POLL_MAX_MS"); s != "" {
		if ms, err := strconv.Atoi(s); err == nil && ms > 0 {
			maxPoll = time.Duration(ms) * time.Millisecond
		}
	}
	pollDelay := initPoll
	pollTimer := time.NewTimer(pollDelay)
	capacity := nameCapacity(c.domain)
	overhead := 8 + 1 + numPadding
	payloadLimit := capacity - overhead
	if payloadLimit < 0 {
		payloadLimit = 0
	}
	var sendFailures int
	for {
		var packets [][]byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		unstash := c.QueuePacketConn.Unstash(addr)
		pollTimerExpired := false

		// Prefer stashed packet, then outgoing, then poll/timer.
		select {
		case p := <-unstash:
			packets = append(packets, p)
		case p := <-outgoing:
			packets = append(packets, p)
		default:
			select {
			case p := <-unstash:
				packets = append(packets, p)
			case p := <-outgoing:
				packets = append(packets, p)
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(packets) > 0 {
			select {
			case <-c.pollChan:
			default:
			}
			used := 0
			for _, p := range packets {
				used += 1 + len(p)
			}
			for used < payloadLimit {
				select {
				case p := <-unstash:
					if 1+len(p) > payloadLimit-used {
						c.QueuePacketConn.Stash(p, addr)
						goto done
					}
					packets = append(packets, p)
					used += 1 + len(p)
				case p := <-outgoing:
					if 1+len(p) > payloadLimit-used {
						c.QueuePacketConn.Stash(p, addr)
						goto done
					}
					packets = append(packets, p)
					used += 1 + len(p)
				default:
					goto done
				}
			}
		done:
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPoll {
				pollDelay = maxPoll
			}
		} else {
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPoll
		}
		pollTimer.Reset(pollDelay)

		if err := c.send(transport, packets, addr); err != nil {
			sendFailures++
			if sendFailures >= rateLimitBackoffThreshold {
				pollDelay = time.Duration(float64(pollDelay) * rateLimitBackoffMultiplier)
				if pollDelay > maxPoll {
					pollDelay = maxPoll
				}
				sendFailures = 0
				log.Printf("send failed %d times: %v; backing off poll to %v", rateLimitBackoffThreshold, err, pollDelay)
			} else {
				log.Printf("send: %v", err)
			}
		} else {
			sendFailures = 0
			if pollDelay > initPoll {
				pollDelay = initPoll
			}
		}
	}
}
