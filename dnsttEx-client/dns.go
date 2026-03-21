// DNSPacketConn struct, constructor, and shared helpers. Receive path in
// dns_recv.go; send path in dns_send.go; Base36 in dns_encoding.go; SOCKS log in dns_socks_log.go.
package main

import (
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
)

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
	// server hint callback + dedupe state for downstream hint frames (flag 0x01).
	hintMu            sync.Mutex
	serverHintHandler func(dns.DownstreamHint)
	lastHint          dns.DownstreamHint
	lastHintAt        time.Time
	lastHintValid     bool
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// SetServerHintHandler installs/removes a callback for server downstream hint frames.
// The callback should be fast and non-blocking.
func (c *DNSPacketConn) SetServerHintHandler(h func(dns.DownstreamHint)) {
	c.hintMu.Lock()
	defer c.hintMu.Unlock()
	c.serverHintHandler = h
}

func (c *DNSPacketConn) maybeDispatchServerHint(h dns.DownstreamHint) {
	ttl := time.Duration(h.HintTTLms) * time.Millisecond
	if ttl <= 0 {
		ttl = 250 * time.Millisecond
	}
	now := time.Now()

	c.hintMu.Lock()
	if c.lastHintValid &&
		c.lastHint.FirstMissingSN == h.FirstMissingSN &&
		c.lastHint.HighestSentSN == h.HighestSentSN &&
		c.lastHint.SuggestedCount == h.SuggestedCount &&
		now.Sub(c.lastHintAt) < ttl {
		c.hintMu.Unlock()
		return
	}
	c.lastHint = h
	c.lastHintAt = now
	c.lastHintValid = true
	handler := c.serverHintHandler
	c.hintMu.Unlock()

	if handler != nil {
		handler(h)
	}
}

// KCPMTUHint returns the largest single tunnel packet that can fit in one DNS
// query on the current request path, after accounting for DNSPacketConn's
// clientID/mode framing and any request-size cap discovered by MTU probing.
//
// This MUST match buildUpstreamPayload for one segment: clientID(8) + v2 marker(1) +
// maxResp hint(2) + 1-byte length prefix(1) + numPadding + payload.
// sendLoop uses overhead 8+1+2+numPadding and per-segment used += 1+len(p); same total 12+len.
// If hint is too large, send() will stash every full-MSS segment and spin on poll+unstash (no timer).
func (c *DNSPacketConn) KCPMTUHint() int {
	framing := 8 + 1 + 2 + 1 + numPadding
	hint := c.effectiveSendCapacity() - framing
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
