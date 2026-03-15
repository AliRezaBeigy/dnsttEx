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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"
)

// DataPathReporter is implemented by transports (e.g. ResolverPool) that track
// per-endpoint data-path health. recvLoop calls these methods so the pool can
// deprioritize resolvers that return SERVFAIL for tunnel queries while passing
// health probes.
type DataPathReporter interface {
	ConfirmDataPath(addr net.Addr)
	ReportServfail(addr net.Addr)
}

// EDNS option codes (used when resolver forwards them; name-based is fallback for 8.8.8.8 etc).
const (
	upstreamEDNSOptionCode   = 0xFF00
	downstreamEDNSOptionCode = 0xFF01
)

const (
	numPadding        = 0
	numPaddingForPoll = 8

	initPollDelay    = 1 * time.Second
	maxPollDelay     = 1 * time.Second
	initSendCoalesce = 0 * time.Second

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

func truncHex(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return b[:max]
}

// describeHTTPRequest parses the start of stream as an HTTP request and returns
// a one-line description (e.g. "HTTP GET /path HTTP/1.1 Host: example.com").
// Returns empty string if stream does not look like an HTTP request.
func describeHTTPRequest(stream []byte) string {
	line, rest := cutLine(stream)
	if len(line) == 0 {
		return ""
	}
	// Request line: METHOD URI HTTP/1.x
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(strings.ToUpper(parts[2]), "HTTP/") {
		return ""
	}
	method := strings.ToUpper(parts[0])
	uri := parts[1]
	reqLine := fmt.Sprintf("HTTP %s %s %s", method, uri, parts[2])
	host := findHTTPHeader(rest, "Host")
	if host != "" {
		return reqLine + " Host: " + host
	}
	return reqLine
}

// describeHTTPResponse parses the start of stream as an HTTP response and
// returns a one-line description (e.g. "HTTP/1.1 200 OK Content-Length: 123").
// Returns empty string if stream does not look like an HTTP response.
func describeHTTPResponse(stream []byte) string {
	line, rest := cutLine(stream)
	if len(line) == 0 {
		return ""
	}
	// Status line: HTTP/1.x CODE reason
	if !bytes.HasPrefix(line, []byte("HTTP/")) {
		return ""
	}
	statusLine := string(line)
	cl := findHTTPHeader(rest, "Content-Length")
	if cl != "" {
		return statusLine + " Content-Length: " + cl
	}
	return statusLine
}

// cutLine returns the first line (without \r\n or \n) and the rest of buf.
func cutLine(buf []byte) (line []byte, rest []byte) {
	for i := 0; i < len(buf); i++ {
		if buf[i] == '\n' {
			line = buf[:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			rest = buf[i+1:]
			return line, rest
		}
	}
	return buf, nil
}

// findHTTPHeader looks for "Key: value" in buf (headers section), case-insensitive key.
// Stops at first empty line (end of headers).
func findHTTPHeader(buf []byte, key string) string {
	keyLower := strings.ToLower(key)
	for len(buf) > 0 {
		line, next := cutLine(buf)
		if len(line) == 0 {
			return "" // end of headers
		}
		if i := bytes.IndexByte(line, ':'); i > 0 {
			k := strings.TrimSpace(string(line[:i]))
			if strings.ToLower(k) == keyLower {
				return strings.TrimSpace(string(line[i+1:]))
			}
		}
		buf = next
	}
	return ""
}

// FormatDownstreamForSocksLog returns a short parsed description of downstream
// data (SOCKS5 reply, HTTP response, or relay length). Used for client-edge
// logging in main.go (incoming/outgoing to local app) and tunnel-layer DNSTT_RX_DATA logs.
func FormatDownstreamForSocksLog(stream []byte) string {
	if len(stream) == 0 {
		return "0 B"
	}
	// SOCKS5 reply: VER=0x05 REP RSV ATYP BND.ADDR BND.PORT
	if len(stream) >= 4 && stream[0] == 0x05 {
		rep := stream[1]
		repStr := "ok"
		switch rep {
		case 0x00:
			repStr = "ok"
		case 0x01:
			repStr = "general failure"
		case 0x02:
			repStr = "not allowed"
		case 0x03:
			repStr = "network unreachable"
		case 0x04:
			repStr = "host unreachable"
		case 0x05:
			repStr = "connection refused"
		case 0x07:
			repStr = "command not supported"
		case 0x08:
			repStr = "address type not supported"
		default:
			repStr = fmt.Sprintf("rep=%d", rep)
		}
		atyp := stream[3]
		var bound string
		var consumed int
		switch atyp {
		case 0x01: // IPv4
			if len(stream) >= 10 {
				bound = net.IP(stream[4:8]).String()
				port := binary.BigEndian.Uint16(stream[8:10])
				bound = net.JoinHostPort(bound, strconv.Itoa(int(port)))
				consumed = 10
			} else {
				bound = "?"
				consumed = 4
			}
		case 0x03: // domain
			if len(stream) >= 5 {
				dLen := int(stream[4])
				if len(stream) >= 5+dLen+2 {
					bound = string(stream[5 : 5+dLen])
					port := binary.BigEndian.Uint16(stream[5+dLen : 7+dLen])
					bound = net.JoinHostPort(bound, strconv.Itoa(int(port)))
					consumed = 7 + dLen
				} else {
					bound = "?"
					consumed = 5
				}
			} else {
				bound = "?"
				consumed = 4
			}
		case 0x04: // IPv6
			if len(stream) >= 22 {
				bound = net.IP(stream[4:20]).String()
				port := binary.BigEndian.Uint16(stream[20:22])
				bound = net.JoinHostPort(bound, strconv.Itoa(int(port)))
				consumed = 22
			} else {
				bound = "?"
				consumed = 4
			}
		default:
			bound = "?"
			consumed = 4
		}
		s := fmt.Sprintf("SOCKS5 reply %s bound=%s", repStr, bound)
		if consumed < len(stream) {
			trailing := stream[consumed:]
			if desc := describeHTTPResponse(trailing); desc != "" {
				s += " | " + desc
			} else {
				s += fmt.Sprintf(" + %d B data", len(trailing))
			}
		}
		return s
	}
	if desc := describeHTTPResponse(stream); desc != "" {
		return desc
	}
	return fmt.Sprintf("relay %d B", len(stream))
}

// FormatUpstreamForSocksLog returns a short parsed description of upstream
// data (SOCKS5 greeting/CONNECT, HTTP request, or relay length). Used for
// client-edge logging in main.go and tunnel-layer DNSTT_TX_DATA logs.
func FormatUpstreamForSocksLog(stream []byte) string {
	if len(stream) == 0 {
		return "0 B"
	}
	// SOCKS5 CONNECT request: VER=0x05 CMD=0x01 RSV=0x00 ATYP DST.ADDR DST.PORT
	if len(stream) >= 4 && stream[0] == 0x05 && stream[1] == 0x01 && stream[2] == 0x00 {
		atyp := stream[3]
		var dest string
		var consumed int
		switch atyp {
		case 0x01: // IPv4
			if len(stream) >= 10 {
				dest = net.IP(stream[4:8]).String()
				port := binary.BigEndian.Uint16(stream[8:10])
				dest = net.JoinHostPort(dest, strconv.Itoa(int(port)))
				consumed = 10
			} else {
				dest = "?"
				consumed = 4
			}
		case 0x03: // domain
			if len(stream) >= 5 {
				dLen := int(stream[4])
				if len(stream) >= 5+dLen+2 {
					dest = string(stream[5 : 5+dLen])
					port := binary.BigEndian.Uint16(stream[5+dLen : 7+dLen])
					dest = net.JoinHostPort(dest, strconv.Itoa(int(port)))
					consumed = 7 + dLen
				} else {
					dest = "?"
					consumed = 5
				}
			} else {
				dest = "?"
				consumed = 4
			}
		case 0x04: // IPv6
			if len(stream) >= 22 {
				dest = net.IP(stream[4:20]).String()
				port := binary.BigEndian.Uint16(stream[20:22])
				dest = net.JoinHostPort(dest, strconv.Itoa(int(port)))
				consumed = 22
			} else {
				dest = "?"
				consumed = 4
			}
		default:
			dest = "?"
			consumed = 4
		}
		s := fmt.Sprintf("SOCKS5 CONNECT %s", dest)
		if consumed < len(stream) {
			trailing := stream[consumed:]
			if desc := describeHTTPRequest(trailing); desc != "" {
				s += " | " + desc
			} else {
				s += fmt.Sprintf(" + %d B data", len(trailing))
			}
		}
		return s
	}
	// SOCKS5 greeting: VER=0x05 NMETHODS METHODS...
	if len(stream) >= 2 && stream[0] == 0x05 {
		nMethods := int(stream[1])
		consumed := 2 + nMethods
		if consumed > len(stream) {
			consumed = len(stream)
		}
		s := fmt.Sprintf("SOCKS5 greeting %d method(s)", nMethods)
		if consumed < len(stream) {
			trailing := stream[consumed:]
			if desc := describeHTTPRequest(trailing); desc != "" {
				s += " | " + desc
			} else {
				s += fmt.Sprintf(" + %d B data", len(trailing))
			}
		}
		return s
	}
	if desc := describeHTTPRequest(stream); desc != "" {
		return desc
	}
	return fmt.Sprintf("relay %d B", len(stream))
}

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
	maxRequestSize  int // max question QNAME wire length (octets); DPI-style limit, not full UDP size; 0 = nameCapacity only
	// Sending on pollChan permits sendLoop to send an empty polling query.
	// sendLoop also does its own polling according to a time schedule.
	pollChan chan struct{}
	// inFlightCap limits how many data-carrying queries can be in flight
	// concurrently. sendLoop blocks until inFlightCount < inFlightCap before
	// sending a data query. recvLoop decrements inFlightCount (floor 0) on
	// every DNS response and signals inFlightSignal so sendLoop can wake up.
	// A timeout in sendLoop prevents permanent stall if responses are lost.
	inFlightCap    int32
	inFlightCount  atomic.Int32
	inFlightSignal chan struct{}
	// pendingRetryMu protects pendingRetry and pendingRetryCount (NXDOMAIN retry).
	pendingRetryMu    sync.Mutex
	pendingRetry      [][]byte // copy of last sent data batch, for re-queue on NXDOMAIN
	pendingRetryCount int      // number of times we've re-queued this batch due to NXDOMAIN
	// TC=1 (truncated) response handling: resolver truncated a response that was
	// too large. We track this to dynamically reduce maxResponseSize and trigger re-polls.
	truncatedCount atomic.Uint64 // total TC=1 responses seen (for logging)
	truncatedOnce  sync.Once     // log warning only once
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

// KCPMTUHint returns the largest single tunnel packet that can fit in one DNS
// query on the current request path, after accounting for DNSPacketConn's
// clientID/mode framing and any request-size cap discovered by MTU probing.
func (c *DNSPacketConn) KCPMTUHint() int {
	hint := c.effectiveSendCapacity() - (8 + 1)
	if hint < 0 {
		return 0
	}
	if hint > maxPacketSize {
		hint = maxPacketSize
	}
	return hint
}

// NewDNSPacketConn creates a new DNSPacketConn. transport, through its WriteTo
// and ReadFrom methods, handles the actual sending and receiving the DNS
// messages encoded by DNSPacketConn. addr is the address to be passed to
// transport.WriteTo whenever a message needs to be sent. maxResponseSize is the
// max response size to request from the server (OPT Class); 0 means 4096.
// maxRequestSize is the max question QNAME wire length (octets); 0 means
// nameCapacity only (no MTU-based limit).
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
	// Limit concurrent in-flight data queries to avoid flooding the resolver.
	// Low-MTU paths get a tighter default; normal paths use a generous limit.
	// Override with DNSTT_INFLIGHT_CAP (0 = no limit).
	{
		cap := int32(0)
		if s := os.Getenv("DNSTT_INFLIGHT_CAP"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v >= 0 {
				cap = int32(v)
			}
		}
		if cap > 0 {
			c.inFlightCap = cap
			c.inFlightSignal = make(chan struct{}, 1)
		}
		if dnsttDebug() {
			log.Printf("DNSTT_DEBUG: in-flight cap %d (maxRequestSize=%d)", cap, maxRequestSize)
		}
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

		// Decrement in-flight counter on EVERY DNS response (including
		// SERVFAIL, TC=1, etc.) so sendLoop doesn't stall at the cap
		// waiting for responses that will never arrive as rcode=0.
		if c.inFlightCap > 0 {
			if cur := c.inFlightCount.Load(); cur > 0 {
				c.inFlightCount.Add(-1)
			}
			select {
			case c.inFlightSignal <- struct{}{}:
			default:
			}
		}

		// TC=1: the recursive resolver truncated the response because it was
		// too large for the path. The server's downstream data in this response
		// is lost. Trigger immediate re-polls so the server gets new queries to
		// respond to, and dynamically reduce maxResponseSize so subsequent
		// server responses fit.
		if resp.Flags&0x0200 != 0 {
			cnt := c.truncatedCount.Add(1)
			c.truncatedOnce.Do(func() {
				log.Printf("WARNING: DNS response truncated (TC=1) by resolver — server data lost; reducing max response size")
			})
			if dnsttDebug() {
				qName := ""
				if len(resp.Question) >= 1 {
					qName = resp.Question[0].Name.String()
				}
				log.Printf("DNSTT_DEBUG: TC=1 truncated response #%d for %s (wire %d bytes)", cnt, qName, n)
			}
			// Reduce maxResponseSize: step down to the next lower safe value.
			// This affects all future queries' OPT Class field.
			if c.maxResponseSize > 256 {
				newMax := c.maxResponseSize * 3 / 4
				if newMax < 256 {
					newMax = 256
				}
				c.maxResponseSize = newMax
				log.Printf("Reduced max response size to %d bytes due to truncation", newMax)
			}
			// Trigger 2 immediate re-polls so the server has queries to respond
			// to with the data it couldn't deliver in the truncated response.
			for i := 0; i < 2; i++ {
				select {
				case c.pollChan <- struct{}{}:
				default:
				}
			}
		}

		rcode := resp.Flags & 0x000f

		// SERVFAIL (rcode 2): the recursive resolver could not reach the
		// authoritative server or it timed out. This is a resolver-level
		// failure — the tunnel data in the query was lost, but retrying the
		// same data to the SAME resolver won't help. Instead:
		//  1. Tell the pool to deprioritize this resolver (mark it "cold").
		//  2. Trigger a re-poll so the server gets a new query from a working resolver.
		//  3. Let KCP handle retransmission of the lost segment.
		if rcode == dns.RcodeServerFailure {
			qName := ""
			if len(resp.Question) >= 1 {
				qName = resp.Question[0].Name.String()
			}
			if dnsttDebug() {
				log.Printf("DNSTT_DEBUG: SERVFAIL (rcode 2) for query %s from %s", qName, addr)
			}
			if reporter, ok := transport.(DataPathReporter); ok {
				reporter.ReportServfail(addr)
			}
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
			continue
		}

		// Other non-zero rcodes (NXDOMAIN etc): re-queue last data batch
		// and retry up to nxdomainRetryMax times.
		if rcode != dns.RcodeNoError {
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

		// Successful response (rcode=0). Confirm data-path health for
		// this resolver so the pool keeps it in the "responsive" set.
		if reporter, ok := transport.(DataPathReporter); ok {
			reporter.ConfirmDataPath(addr)
		}

		payload := dnsResponsePayload(&resp, c.domain)
		if dnsttLogRxData() {
			if len(payload) == 0 {
				log.Printf("DNSTT_RX_POLL_EMPTY ← from %s | no TXT/downstream (nothing to read yet)", addr)
			}
		}
		if len(payload) == 0 {
			continue
		}
		// Health PONG / scan — not tunneled data.
		if bytes.Equal(payload, ProbeResponsePONG) {
			if dnsttLogRxData() {
				log.Printf("DNSTT_RX_POLL_EMPTY ← from %s | PONG only (health / idle)", addr)
			}
			continue
		}

		// Pull out the packets contained in the payload (length-prefixed tunnel stream).
		r := bytes.NewReader(payload)
		any := false
		var recvBytes uint64
		nPackets := 0
		var downstreamBuf []byte
		if dnsttLogRxData() {
			downstreamBuf = make([]byte, 0, len(payload))
		}
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			nPackets++
			recvBytes += uint64(len(p))
			if dnsttLogRxData() {
				downstreamBuf = append(downstreamBuf, p...)
			}
			c.QueuePacketConn.QueueIncoming(p, addr)
		}
		if any && dnsttLogRxData() {
			desc := FormatDownstreamForSocksLog(downstreamBuf)
			log.Printf("DNSTT_RX_DATA ← from %s | %d packet(s) | downstream %d B | %s",
				addr, nPackets, int(recvBytes), desc)
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

// dnsQuestionQNameWireLen returns the wire length in octets of the first
// question's QNAME (length-prefixed labels through root). This matches what
// many DPI systems enforce—not full UDP DNS message size.
func dnsQuestionQNameWireLen(msg []byte) (int, bool) {
	if len(msg) < 13 {
		return 0, false
	}
	i := 12
	for i < len(msg) {
		l := int(msg[i])
		if l == 0 {
			return i - 12 + 1, true
		}
		if l&0xC0 == 0xC0 || l > 63 {
			return 0, false
		}
		i += 1 + l
		if i > len(msg) {
			return 0, false
		}
	}
	return 0, false
}

// maxDecodedPayloadForMaxQName returns the maximum decoded payload length that
// fits in a query whose question QNAME wire length is at most maxQName.
func (c *DNSPacketConn) maxDecodedPayloadForMaxQName(maxQName int) int {
	if maxQName <= 0 {
		return nameCapacity(c.domain)
	}
	capByName := nameCapacity(c.domain)
	lo, hi := 0, capByName+1
	for lo+1 < hi {
		mid := (lo + hi) / 2
		dummy := make([]byte, mid)
		wire, err := c.buildQueryWire(dummy, 0)
		if err != nil {
			hi = mid
			continue
		}
		qnl, ok := dnsQuestionQNameWireLen(wire)
		if !ok {
			hi = mid
			continue
		}
		if qnl <= maxQName {
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
	capByMTU := c.maxDecodedPayloadForMaxQName(c.maxRequestSize)
	if capByMTU < capByName {
		return capByMTU
	}
	return capByName
}

// buildUpstreamPayload builds raw payload with compact framing:
//   - ClientID(8) + mode byte. Mode: 0 = poll (no data); 0xFE = poll with 2-byte response-size hint;
//     1–223 = single packet of that length; 224+ = legacy (224+nPad, nPad bytes, then [1-byte len + packet]*).
//     For poll (no data), random bytes are appended so each query name differs (avoids DNS/resolver cache).
//
// maxRespHint is the max DNS response size (from MTU discovery) to embed in poll payloads so
// the server can cap responses even when recursive resolvers rewrite the OPT Class field.
// Pass 0 to omit the hint (legacy poll).
func (c *DNSPacketConn) buildUpstreamPayload(packets [][]byte, maxRespHint int) []byte {
	var buf bytes.Buffer
	buf.Write(c.clientID[:])
	if len(packets) == 0 {
		if maxRespHint > 0 && maxRespHint <= 0xFFFF {
			buf.WriteByte(probeModeHintPoll)
			buf.WriteByte(byte(maxRespHint >> 8))
			buf.WriteByte(byte(maxRespHint))
		} else {
			buf.WriteByte(0) // legacy poll
		}
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
	// In-band response-size hint: embed in QNAME so the server sees the real
	// limit even when recursive resolvers rewrite the OPT Class field.
	respHint := maxRespOverride
	if respHint <= 0 {
		respHint = c.maxResponseSize
	}

	capacity := c.effectiveSendCapacity()
	if maxReqOverride > 0 {
		capacity = c.maxDecodedPayloadForMaxQName(maxReqOverride)
	}
	decoded := c.buildUpstreamPayload(packets, respHint)
	for len(decoded) > capacity && len(packets) > 1 {
		// Stash last packet and try again with fewer.
		c.QueuePacketConn.Stash(packets[len(packets)-1], addr)
		packets = packets[:len(packets)-1]
		decoded = c.buildUpstreamPayload(packets, respHint)
	}
	if len(decoded) > capacity && len(packets) == 1 {
		c.QueuePacketConn.Stash(packets[0], addr)
		decoded = c.buildUpstreamPayload(nil, respHint)
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
		qnl, qok := dnsQuestionQNameWireLen(buf)
		if !qok {
			return fmt.Errorf("send: built query has no parsable QNAME")
		}
		sendAnyway := len(packets) == 0 && len(decoded) <= 11+probeNoiseLen // minimal poll payload (may include 2-byte hint)
		if maxReq <= 0 || qnl <= maxReq || sendAnyway {
			if dnsttDebug() && len(packets) > 0 {
				log.Printf("DNSTT_DEBUG: send: QNAME %d bytes, query wire %d (max QNAME %d)", qnl, len(buf), maxReq)
			}
			if dnsttLogRxData() && len(packets) > 0 {
				desc := FormatUpstreamForSocksLog(decoded)
				log.Printf("DNSTT_TX_DATA → to %s | %d tunnel segment(s) | upstream %d B | QNAME %d | %s",
					addr, len(packets), len(decoded), qnl, desc)
			}
			if len(buf) >= 2 {
				rand.Read(buf[0:2])
			}
			_, err = transport.WriteTo(buf, addr)
			return err
		}
		// Built query QNAME exceeds path limit; reduce payload and retry.
		if len(packets) <= 1 {
			if len(packets) == 1 {
				c.QueuePacketConn.Stash(packets[0], addr)
			}
			decoded = c.buildUpstreamPayload(nil, respHint)
			packets = nil
		} else {
			c.QueuePacketConn.Stash(packets[len(packets)-1], addr)
			packets = packets[:len(packets)-1]
			decoded = c.buildUpstreamPayload(packets, respHint)
		}
	}
}

// Probe mode bytes (first byte of payload after clientID).
const (
	probeModePoll     = 0    // normal idle poll
	probeModeHintPoll = 0xFE // poll with 2-byte max-response-size hint (survives OPT Class rewriting by resolvers)
	probeModePING     = 0xFF // health-check PING; server must respond with PONG
)

// Probe message builders and verifiers: see dns_probe.go.

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
	// Low-MTU paths (e.g. 128-byte request limit) have tiny payloads per
	// query; use shorter coalesce and poll timers to maintain reasonable
	// throughput instead of the default 2s intervals.
	if c.maxRequestSize > 0 && c.maxRequestSize <= 256 {
		if initPoll > 1*time.Second {
			initPoll = 1 * time.Second
		}
		if maxPoll > 1*time.Second {
			maxPoll = 1 * time.Second
		}
		if sendCoalesce > 500*time.Millisecond {
			sendCoalesce = 500 * time.Millisecond
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
				capacity = c.maxDecodedPayloadForMaxQName(maxReqOverride)
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
			// Wait until fewer than inFlightCap data queries are outstanding.
			// Timeout after 3s to recover from lost responses (e.g. queries sent to
			// non-responsive resolvers via ISP DNS interception).
			if c.inFlightCap > 0 {
				for c.inFlightCount.Load() >= c.inFlightCap {
					select {
					case <-c.inFlightSignal:
					case <-time.After(3 * time.Second):
						log.Printf("in-flight cap stall: count=%d cap=%d; resetting (responses may have been lost)", c.inFlightCount.Load(), c.inFlightCap)
						c.inFlightCount.Store(0)
					}
				}
				c.inFlightCount.Add(1)
			}
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
								select {
								case <-coalesceTimer.C:
								default:
								}
							}
							goto done
						}
						packets = append(packets, p)
						used += 1 + len(p)
					case p := <-outgoing:
						if 1+len(p) > payloadLimit-used {
							c.QueuePacketConn.Stash(p, addr)
							if !coalesceTimer.Stop() {
								select {
								case <-coalesceTimer.C:
								default:
								}
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
					select {
					case <-coalesceTimer.C:
					default:
					}
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
