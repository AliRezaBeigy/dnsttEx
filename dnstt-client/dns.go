package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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

	initPollDelay    = 2 * time.Second
	maxPollDelay     = 2 * time.Second
	initSendCoalesce = 2 * time.Second

	pollDelayMultiplier = 2.0
	pollLimit           = 16

	maxPacketSize = 223 // max packet size (1-byte length prefix)

	// RFC 1035 max is 63; 57 leaves more room in 253-octet name.
	maxLabelLen = 57
	// Consecutive send errors before we back off poll rate (resolver rate limiting).
	rateLimitBackoffThreshold  = 3
	rateLimitBackoffMultiplier = 2.0

	// nxdomainRetryMax: when we receive NXDOMAIN, re-queue the last data batch and retry up to this many times before giving up.
	nxdomainRetryMax = 3
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
	maxRequestSize  int // max request (query) wire size from MTU discovery; 0 = use nameCapacity only
	// Sending on pollChan permits sendLoop to send an empty polling query.
	// sendLoop also does its own polling according to a time schedule.
	pollChan chan struct{}
	// pendingRetryMu protects pendingRetry and pendingRetryCount (NXDOMAIN retry).
	pendingRetryMu    sync.Mutex
	pendingRetry      [][]byte // copy of last sent data batch, for re-queue on NXDOMAIN
	pendingRetryCount int      // number of times we've re-queued this batch due to NXDOMAIN
	// Stats for periodic report (DNSTT_STATS=1 or DNSTT_DEBUG): atomics, reset every second.
	statsQueriesSent        atomic.Uint64
	statsTunnelBytesSent    atomic.Uint64
	statsPollsSent          atomic.Uint64
	statsResponsesRecv      atomic.Uint64 // responses that contained tunnel payload
	statsTunnelBytesRecv    atomic.Uint64
	statsResponsesRecvTotal atomic.Uint64 // any DNS response received (to see empty vs none)
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
// maxRequestSize is the max request (query) wire size from MTU discovery; 0
// means use nameCapacity only (no MTU-based limit).
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, maxResponseSize, maxRequestSize int) *DNSPacketConn {
	// Generate a new random ClientID.
	clientID := turbotunnel.NewClientID()
	c := &DNSPacketConn{
		clientID:        clientID,
		domain:          domain,
		maxResponseSize: maxResponseSize,
		maxRequestSize:  maxRequestSize,
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
	if os.Getenv("DNSTT_STATS") != "" || os.Getenv("DNSTT_DEBUG") != "" {
		go c.statsReportLoop()
	}
	return c
}

// statsReportLoop logs send/recv stats every second to diagnose bursts (DNSTT_STATS=1 or DNSTT_DEBUG).
func (c *DNSPacketConn) statsReportLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		q := c.statsQueriesSent.Swap(0)
		txBytes := c.statsTunnelBytesSent.Swap(0)
		polls := c.statsPollsSent.Swap(0)
		rxTotal := c.statsResponsesRecvTotal.Swap(0)
		rxWithPayload := c.statsResponsesRecv.Swap(0)
		rxBytes := c.statsTunnelBytesRecv.Swap(0)
		dataQueries := q - polls
		log.Printf("DNSTT_STATS: last 1s — sent %d queries (%d data, %d polls) %d bytes tunnel | recv %d DNS (%d with payload) %d bytes tunnel",
			q, dataQueries, polls, txBytes, rxTotal, rxWithPayload, rxBytes)
	}
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
		c.statsResponsesRecvTotal.Add(1)

		rcode := resp.Flags & 0x000f
		if rcode != dns.RcodeNoError {
			// Server or path returned an error (e.g. NXDOMAIN). Re-queue last data batch and retry up to nxdomainRetryMax times.
			qName := ""
			if len(resp.Question) >= 1 {
				qName = resp.Question[0].Name.String()
			}
			rcodeStr := "error"
			if rcode == dns.RcodeNameError {
				rcodeStr = "NXDOMAIN (No such name)"
			}
			c.pendingRetryMu.Lock()
			if c.pendingRetry != nil && c.pendingRetryCount < nxdomainRetryMax {
				for _, p := range c.pendingRetry {
					c.WriteTo(p, addr)
				}
				c.pendingRetryCount++
				retryNum := c.pendingRetryCount
				c.pendingRetryMu.Unlock()
				log.Printf("DNS response %s (rcode %d) for query %s — retrying (%d/%d)", rcodeStr, rcode, qName, retryNum, nxdomainRetryMax)
			} else {
				if c.pendingRetry != nil && c.pendingRetryCount >= nxdomainRetryMax {
					log.Printf("DNS response %s (rcode %d) for query %s — gave up after %d retries", rcodeStr, rcode, qName, nxdomainRetryMax)
					c.pendingRetry = nil
				} else {
					log.Printf("DNS response %s (rcode %d) for query %s — check server logs for reason", rcodeStr, rcode, qName)
				}
				c.pendingRetryMu.Unlock()
			}
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		any := false
		var recvBytes uint64
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			recvBytes += uint64(len(p))
			c.QueuePacketConn.QueueIncoming(p, addr)
		}
		if any {
			c.statsResponsesRecv.Add(1)
			c.statsTunnelBytesRecv.Add(recvBytes)
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

// buildQueryWire builds the DNS query wire bytes from decoded upstream payload.
// optMaxResp: when > 0, use as OPT Class (max response size for server); when 0, use c.maxResponseSize.
func (c *DNSPacketConn) buildQueryWire(decoded []byte, optMaxResp int) ([]byte, error) {
	encoded := make([]byte, base36EncodedLen(len(decoded)))
	base36Encode(encoded, decoded)
	labels := chunks(encoded, maxLabelLen)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return nil, err
	}
	optClass := uint16(4096)
	if optMaxResp > 0 {
		optClass = uint16(optMaxResp)
	} else if c.maxResponseSize > 0 {
		optClass = uint16(c.maxResponseSize)
	}
	if optClass > 0 && optClass < 512 {
		optClass = 512
	}
	query := &dns.Message{
		ID:    0,
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

// maxDecodedPayloadForMaxWire returns the maximum decoded payload length that
// fits in a query whose wire size is at most maxWire. Used when maxRequestSize
// (client MTU) is set so we don't send requests larger than the path allows.
func (c *DNSPacketConn) maxDecodedPayloadForMaxWire(maxWire int) int {
	if maxWire <= 0 {
		return nameCapacity(c.domain)
	}
	capByName := nameCapacity(c.domain)
	// Binary search for largest decoded length that fits.
	lo, hi := 0, capByName+1
	for lo+1 < hi {
		mid := (lo + hi) / 2
		dummy := make([]byte, mid)
		wire, err := c.buildQueryWire(dummy, 0)
		if err != nil {
			hi = mid
			continue
		}
		if len(wire) <= maxWire {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

// effectiveSendCapacity returns the max decoded payload length we may send in
// one query: min(nameCapacity, max decoded that fits in maxRequestSize when set).
func (c *DNSPacketConn) effectiveSendCapacity() int {
	capByName := nameCapacity(c.domain)
	if c.maxRequestSize <= 0 {
		return capByName
	}
	capByMTU := c.maxDecodedPayloadForMaxWire(c.maxRequestSize)
	if capByMTU < capByName {
		return capByMTU
	}
	return capByName
}

// buildUpstreamPayload builds raw payload with compact framing:
//   - ClientID(8) + mode byte. Mode: 0 = poll (no data); 1–223 = single packet of that length; 224+ = legacy (224+nPad, nPad bytes, then [1-byte len + packet]*).
//     For poll (no data), random bytes are appended so each query name differs (avoids DNS/resolver cache).
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
// When maxRespOverride > 0 or maxReqOverride > 0 (e.g. from ResolverPool.NextSendMTU), this
// send uses that resolver's MTU: OPT Class = maxRespOverride, payload capped by maxReqOverride.
func (c *DNSPacketConn) send(transport net.PacketConn, packets [][]byte, addr net.Addr, maxRespOverride, maxReqOverride int) error {
	capacity := c.effectiveSendCapacity()
	if maxReqOverride > 0 {
		capacity = c.maxDecodedPayloadForMaxWire(maxReqOverride)
	}
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
	maxReq := c.maxRequestSize
	if maxReqOverride > 0 {
		maxReq = maxReqOverride
	}
	for {
		buf, err := c.buildQueryWire(decoded, maxRespOverride)
		if err != nil {
			return err
		}
		sendAnyway := len(packets) == 0 && len(decoded) <= 9+probeNoiseLen // minimal poll payload
		if maxReq <= 0 || len(buf) <= maxReq || sendAnyway {
			if dnsttDebug() && len(packets) > 0 {
				log.Printf("DNSTT_DEBUG: send: query wire %d bytes (max request %d)", len(buf), maxReq)
			}
			if len(buf) >= 2 {
				rand.Read(buf[0:2])
			}
			_, err = transport.WriteTo(buf, addr)
			return err
		}
		// Built query exceeds path MTU; reduce payload and retry.
		if len(packets) <= 1 {
			if len(packets) == 1 {
				c.QueuePacketConn.Stash(packets[0], addr)
			}
			decoded = c.buildUpstreamPayload(nil)
			packets = nil
		} else {
			c.QueuePacketConn.Stash(packets[len(packets)-1], addr)
			packets = packets[:len(packets)-1]
			decoded = c.buildUpstreamPayload(packets)
		}
	}
}

// Probe mode bytes (first byte of payload after clientID).
const (
	probeModePoll = 0    // normal idle poll
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
	optClass := uint16(responseSize)
	if optClass < 512 {
		optClass = 512 // RFC 6891
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

// maxProbeRequestWireSize is the maximum DNS query wire size we can build for client MTU probes:
// the question name is limited to 255 octets (RFC 1035), so header(12)+name(255)+type(2)+class(2)+OPT(11) ≈ 282.
const maxProbeRequestWireSize = 282

// probeRequestWireSize returns the wire size of a PING probe query with the given raw payload length.
// Used to find the minimum padding so the probe is exactly >= minRequestSize.
func probeRequestWireSize(domain dns.Name, rawLen int) (int, error) {
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
		return 0, err
	}
	return len(wire), nil
}

// BuildProbeMessageWithRequestSize builds a PING probe whose wire size is at least minRequestSize
// bytes (for client MTU discovery). The minimum padding needed is added so the query is just
// >= minRequestSize (we don't overshoot), giving an accurate probe for that request size.
// minRequestSize must be <= maxProbeRequestWireSize or the name would exceed 255 octets.
func BuildProbeMessageWithRequestSize(domain dns.Name, clientID turbotunnel.ClientID, minRequestSize int) ([]byte, error) {
	if minRequestSize > maxProbeRequestWireSize {
		return nil, fmt.Errorf("minRequestSize %d exceeds max DNS query size %d (name limited to 255 octets)", minRequestSize, maxProbeRequestWireSize)
	}
	baseLen := 9 + probeNoiseLen // clientID(8) + PING(1) + noise(6)
	// Binary search for the smallest raw payload length such that wire size >= minRequestSize.
	lo, hi := baseLen, 256
	for lo+1 < hi {
		mid := (lo + hi) / 2
		wireLen, err := probeRequestWireSize(domain, mid)
		if err != nil {
			hi = mid
			continue
		}
		if wireLen >= minRequestSize {
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

// sendLoop batches packets into the question name (limited by effectiveSendCapacity or,
// when using ResolverPool, by the next resolver's MTU). Also sends polling queries when idle.
//
// What we send when no TCP client is connected:
//   - Session handshake: When the session starts, KCP + Noise + smux perform their handshake.
//     They write many small segments to the tunnel; each segment becomes an outgoing packet.
//     sendLoop drains the outgoing queue as fast as it can, so you see a burst of DNS queries
//     (each carrying one or a few KCP segments) until the handshake completes. That burst is
//     normal and can be thousands of queries in the first second.
//   - Idle polls: When the outgoing queue is empty, we send one empty "poll" query per
//     pollDelay (initPollDelay 500ms, or DNSTT_POLL_INIT_MS). Polls give the server a
//     query to respond to and keep the tunnel alive.
//
// Poll timing can be overridden with DNSTT_POLL_INIT_MS and DNSTT_POLL_MAX_MS (e.g. 500/2000 for conservative resolvers).
// DNSTT_SEND_COALESCE_MS: when > 0, wait up to this many ms for more packets before sending (reduces query burst; 0 = send immediately).
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) error {
	initPoll, maxPoll, sendCoalesce := initPollDelay, maxPollDelay, initSendCoalesce
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
	if s := os.Getenv("DNSTT_SEND_COALESCE_MS"); s != "" {
		if ms, err := strconv.Atoi(s); err == nil && ms >= 0 {
			sendCoalesce = time.Duration(ms) * time.Millisecond
		}
	}
	pollDelay := initPoll
	pollTimer := time.NewTimer(pollDelay)
	var sendFailures int
	var lastTunnelSend time.Time // zero until first tunnel send (so first handshake is never delayed by coalesce)
	for {
		// Per-send MTU: when using ResolverPool, use the next resolver's limits so the server gets the right response size and we don't exceed that resolver's request MTU.
		var maxRespOverride, maxReqOverride int
		capacity := c.effectiveSendCapacity()
		if pool, ok := transport.(*ResolverPool); ok {
			maxRespOverride, maxReqOverride = pool.NextSendMTU()
			if maxReqOverride > 0 {
				capacity = c.maxDecodedPayloadForMaxWire(maxReqOverride)
			}
		}
		overhead := 8 + 1 + numPadding
		payloadLimit := capacity - overhead
		if payloadLimit < 0 {
			payloadLimit = 0
		}
		// When payloadLimit is 0 we can only send polls; data packets stay queued until capacity improves.

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
			// Drain more packets that are already queued (non-blocking).
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
			// Coalesce: batch is incomplete (used < payloadLimit). If we've already sent tunnel data at least
			// once, wait up to sendCoalesce for more packets to reduce burst of small queries. Never wait on
			// the first batch so the handshake completes immediately.
			if sendCoalesce > 0 && used < payloadLimit && !lastTunnelSend.IsZero() {
				coalesceTimer := time.NewTimer(sendCoalesce)
				for used < payloadLimit {
					select {
					case p := <-unstash:
						if 1+len(p) > payloadLimit-used {
							c.QueuePacketConn.Stash(p, addr)
							if !coalesceTimer.Stop() {
								select { case <-coalesceTimer.C: default: }
							}
							goto done
						}
						packets = append(packets, p)
						used += 1 + len(p)
					case p := <-outgoing:
						if 1+len(p) > payloadLimit-used {
							c.QueuePacketConn.Stash(p, addr)
							if !coalesceTimer.Stop() {
								select { case <-coalesceTimer.C: default: }
							}
							goto done
						}
						packets = append(packets, p)
						used += 1 + len(p)
					case <-coalesceTimer.C:
						goto done
					}
				}
				if !coalesceTimer.Stop() {
					select { case <-coalesceTimer.C: default: }
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

		if dnsttDebug() {
			if len(packets) > 0 {
				tunnelBytes := 0
				for _, p := range packets {
					tunnelBytes += len(p)
				}
				log.Printf("DNSTT_DEBUG: sendLoop: sending query with %d packet(s), %d bytes tunnel data", len(packets), tunnelBytes)
			} else {
				log.Printf("DNSTT_DEBUG: sendLoop: sending poll (idle)")
			}
		}
		if len(packets) > 0 {
			c.pendingRetryMu.Lock()
			c.pendingRetry = make([][]byte, len(packets))
			for i, p := range packets {
				c.pendingRetry[i] = make([]byte, len(p))
				copy(c.pendingRetry[i], p)
			}
			c.pendingRetryCount = 0
			c.pendingRetryMu.Unlock()
			lastTunnelSend = time.Now()
		}
		if err := c.send(transport, packets, addr, maxRespOverride, maxReqOverride); err != nil {
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
			if len(packets) == 0 {
				c.statsPollsSent.Add(1)
			} else {
				tunnelBytes := uint64(0)
				for _, p := range packets {
					tunnelBytes += uint64(len(p))
				}
				c.statsTunnelBytesSent.Add(tunnelBytes)
			}
			c.statsQueriesSent.Add(1)
		}
	}
}
