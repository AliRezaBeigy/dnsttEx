// The MIT License (MIT)
//
// Copyright (c) 2015 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package kcp

import (
	"container/heap"
	"encoding/binary"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// KCP Protocol Constants
const (
	// Retransmission Timeout (RTO) bounds, in milliseconds
	IKCP_RTO_NDL = 30    // no-delay mode: minimum RTO (ms)
	IKCP_RTO_MIN = 100   // normal mode: minimum RTO (ms)
	IKCP_RTO_DEF = 200   // default RTO (ms)
	IKCP_RTO_MAX = 60000 // maximum RTO (ms), 60 seconds

	// Command types for the KCP segment header (cmd field)
	IKCP_CMD_PUSH = 81 // cmd: push data
	IKCP_CMD_ACK  = 82 // cmd: acknowledge
	IKCP_CMD_WASK = 83 // cmd: window probe request (ask)
	IKCP_CMD_WINS = 84 // cmd: window size response (tell)
	// IKCP_CMD_NREQ: client asks server to resend downstream PUSH payloads starting at sn (header sn),
	// up to una (header una) segments. No payload. dnstt extension; peers must both support it.
	IKCP_CMD_NREQ = 85
	// IKCP_CMD_NMIS: server tells client the NREQ head segment is not in the downstream replay cache.
	// No payload. Wire sn is the same 16-bit form as in NREQ; client expands with rcv_nxt. dnstt extension.
	IKCP_CMD_NMIS = 86
	// maxNreqSegments caps how many sequence numbers one NREQ may cover.
	maxNreqSegments = 128

	// Probe flags (bitfield), set in kcp.probe to schedule probe commands
	IKCP_ASK_SEND = 1 // schedule sending IKCP_CMD_WASK
	IKCP_ASK_TELL = 2 // schedule sending IKCP_CMD_WINS

	// Default window and MTU sizes
	IKCP_WND_SND = 32   // default send window size (packets)
	IKCP_WND_RCV = 32   // default receive window size (packets)
	IKCP_MTU_DEF = 1400 // default MTU (bytes, not including UDP/IP header)

	// Compact wire format for DNS-sized paths (dnstt):
	// conv(2) + cmd/frg(1) + wnd(1) + ts(2) + sn(2) + una(2) + len(2) = 12 bytes.
	// Wire conv is 16 bits; use matching low 16 bits on both peers (see NewConn2).
	IKCP_ACK_FAST    = 3   // fast retransmit trigger threshold (duplicate ACK count)
	IKCP_INTERVAL    = 100 // default flush interval (ms)
	IKCP_OVERHEAD    = 12
	IKCP_DEADLINK    = 20     // max retransmissions before dropping that segment (session stays open)
	IKCP_THRESH_INIT = 2      // initial slow-start threshold (packets)
	IKCP_THRESH_MIN  = 2      // minimum slow-start threshold (packets)
	IKCP_PROBE_INIT  = 500    // initial window probe timeout (ms)
	IKCP_PROBE_LIMIT = 120000 // maximum window probe timeout (ms), 120 seconds
	IKCP_SN_OFFSET   = 6      // byte offset of sequence number (sn) within the segment header
)

type PacketType int8

const (
	IKCP_PACKET_REGULAR PacketType = iota
	IKCP_PACKET_FEC
)

type FlushType int8

const (
	IKCP_FLUSH_ACKONLY FlushType = 1 << iota
	IKCP_FLUSH_FULL
)

type KCPLogType int32

const (
	IKCP_LOG_OUTPUT KCPLogType = 1 << iota
	IKCP_LOG_INPUT
	IKCP_LOG_SEND
	IKCP_LOG_RECV
	IKCP_LOG_OUT_ACK
	IKCP_LOG_OUT_PUSH
	IKCP_LOG_OUT_WASK
	IKCP_LOG_OUT_WINS
	IKCP_LOG_IN_ACK
	IKCP_LOG_IN_PUSH
	IKCP_LOG_IN_WASK
	IKCP_LOG_IN_WINS
)

const (
	IKCP_LOG_OUTPUT_ALL = IKCP_LOG_OUTPUT | IKCP_LOG_OUT_ACK | IKCP_LOG_OUT_PUSH | IKCP_LOG_OUT_WASK | IKCP_LOG_OUT_WINS
	IKCP_LOG_INPUT_ALL  = IKCP_LOG_INPUT | IKCP_LOG_IN_ACK | IKCP_LOG_IN_PUSH | IKCP_LOG_IN_WASK | IKCP_LOG_IN_WINS
	IKCP_LOG_ALL        = IKCP_LOG_OUTPUT_ALL | IKCP_LOG_INPUT_ALL | IKCP_LOG_SEND | IKCP_LOG_RECV
)

// monotonic reference time point
var refTime time.Time = time.Now()

// currentMs returns current elapsed monotonic milliseconds since program startup
func currentMs() uint32 { return uint32(time.Since(refTime) / time.Millisecond) }

// output_callback is a prototype which ought capture conn and call conn.Write
type output_callback func(buf []byte, size int)

// logoutput_callback is a prototype which logging kcp trace output
type logoutput_callback func(msg string, args ...any)

func _itimediff(later, earlier uint32) int32 {
	return (int32)(later - earlier)
}

const kcpSNMod = 65536 // wire carries sn/una in 16 bits (see encodeWireHeader)

// expandSN16 maps a 16-bit-on-wire sequence number into the same epoch as anchor
// (typically rcv_nxt for downstream PUSH, snd_una for ACK/UNA, snd_nxt for NREQ).
func expandSN16(anchor, wire uint32) uint32 {
	w := wire & (kcpSNMod - 1)
	al := int64(anchor & (kcpSNMod - 1))
	wl := int64(w)
	d := wl - al
	if d > 32767 {
		d -= kcpSNMod
	}
	if d < -32768 {
		d += kcpSNMod
	}
	out := int64(anchor) + d
	if out < 0 {
		if anchor > 0 {
			return anchor - 1
		}
		return ^uint32(0)
	}
	return uint32(out)
}

// segment defines a KCP segment
type segment struct {
	conv     uint32
	cmd      uint8
	frg      uint8
	wnd      uint16
	ts       uint32
	sn       uint32
	una      uint32
	rto      uint32
	xmit     uint32
	resendts uint32
	fastack  uint32
	acked    uint32 // mark if the seg has acked
	data     []byte
}

// encodeWireHeader writes the 12-byte KCP header; does not bump OutSegs (for resends).
func (seg *segment) encodeWireHeader(ptr []byte) []byte {
	binary.LittleEndian.PutUint16(ptr, uint16(seg.conv&0xFFFF))
	ptr[2] = uint8((seg.cmd-81)<<6) | (seg.frg & 0x3F)
	ptr[3] = byte(min(uint32(seg.wnd), 255))
	binary.LittleEndian.PutUint16(ptr[4:], uint16(seg.ts&0xFFFF))
	binary.LittleEndian.PutUint16(ptr[6:], uint16(seg.sn&0xFFFF))
	binary.LittleEndian.PutUint16(ptr[8:], uint16(seg.una&0xFFFF))
	binary.LittleEndian.PutUint16(ptr[10:], uint16(len(seg.data)))
	return ptr[IKCP_OVERHEAD:]
}

// encode a segment header (compact 12-byte dnstt layout).
func (seg *segment) encode(ptr []byte) []byte {
	atomic.AddUint64(&DefaultSnmp.OutSegs, 1)
	return seg.encodeWireHeader(ptr)
}

// segmentHeap is a min-heap of segments, used for receiving segments in order
type segmentHeap struct {
	segments []segment
	marks    map[uint32]struct{} // to avoid duplicates
}

func newSegmentHeap() *segmentHeap {
	h := &segmentHeap{
		marks: make(map[uint32]struct{}),
	}
	heap.Init(h)
	return h
}

func (h *segmentHeap) Len() int { return len(h.segments) }

func (h *segmentHeap) Less(i, j int) bool {
	return _itimediff(h.segments[j].sn, h.segments[i].sn) > 0
}

func (h *segmentHeap) Swap(i, j int) { h.segments[i], h.segments[j] = h.segments[j], h.segments[i] }
func (h *segmentHeap) Push(x any) {
	h.segments = append(h.segments, x.(segment))
	h.marks[x.(segment).sn] = struct{}{}
}

func (h *segmentHeap) Pop() any {
	n := len(h.segments)
	x := h.segments[n-1]
	h.segments[n-1] = segment{} // clear reference to avoid memory leak
	h.segments = h.segments[0 : n-1]
	delete(h.marks, x.sn)
	return x
}

func (h *segmentHeap) Has(sn uint32) bool {
	_, exists := h.marks[sn]
	return exists
}

// peekMinSN returns the smallest buffered segment sequence number.
func (h *segmentHeap) peekMinSN() (sn uint32, ok bool) {
	if len(h.segments) == 0 {
		return 0, false
	}
	return h.segments[0].sn, true
}

// KCP defines a single KCP connection's protocol state machine.
// It is a pure ARQ (Automatic Repeat reQuest) implementation with no I/O.
type KCP struct {
	// Connection identity and framing
	conv  uint32 // conversation id, must be equal on both sides
	mtu   uint32 // maximum transmission unit (bytes)
	mss   uint32 // maximum segment size = mtu - IKCP_OVERHEAD
	state uint32 // connection state, 0 = active, 0xFFFFFFFF = dead link (unused when segment drop is used)

	// Sequence numbers and acknowledgment tracking
	snd_una uint32 // oldest unacknowledged sequence number
	snd_nxt uint32 // next sequence number to send
	rcv_nxt uint32 // next expected sequence number to receive

	// Congestion control (RFC 5681 / RFC 6937)
	ssthresh           uint32 // slow-start threshold (packets)
	rx_rttvar, rx_srtt int32  // RTT variance and smoothed RTT (ms), per RFC 6298
	rx_rto, rx_minrto  uint32 // retransmission timeout and its lower bound (ms)
	snd_wnd            uint32 // local send window size (packets)
	rcv_wnd            uint32 // local receive window size (packets)
	rmt_wnd            uint32 // remote advertised window size (packets)
	cwnd               uint32 // congestion window (packets)
	incr               uint32 // bytes accumulated for cwnd increment

	// Window probing
	probe      uint32 // probe flags (IKCP_ASK_SEND / IKCP_ASK_TELL)
	ts_probe   uint32 // timestamp for next window probe (ms)
	probe_wait uint32 // current probe timeout (ms), doubles on each retry

	// Timers and scheduling
	interval uint32 // flush interval (ms)
	ts_flush uint32 // next flush timestamp (ms)
	nodelay  uint32 // 0: normal, 1: no-delay mode (reduces RTO aggressively)
	updated  uint32 // whether Update() has been called at least once

	// Reliability
	dead_link                uint32 // max retransmit count before link is considered dead
	fastresend               int32  // fast retransmit trigger count, 0 = disabled
	nocwnd                   int32  // 1 = disable congestion control
	stream                   int32  // 1 = stream mode (no message boundaries), 0 = message mode
	assumeDeliveredAfterSend bool   // when true, sender drops PUSH segments right after first transmit (no ACK wait/retransmit)
	suppressOutgoingACK      bool   // when true, do not emit ACKs for received PUSH segments

	// Logging
	logmask KCPLogType
	// recvGapLogged: with DNSTT_KCP_RECV_GAP, log at most once per stalled rcv_nxt (same hole).
	recvGapLogged bool
	// Throttle client log for IKCP_CMD_NMIS (server replay miss) per missing sn.
	lastReplayMissFullSn uint32 // 0xFFFFFFFF = unset
	lastReplayMissLogMs  uint32

	// Data queues and buffers
	snd_queue *RingBuffer[segment] // send queue: segments waiting to enter the send window
	rcv_queue *RingBuffer[segment] // receive queue: ordered segments ready for user read
	snd_buf   *RingBuffer[segment] // send buffer: segments in-flight (sent but unacknowledged)
	rcv_buf   *segmentHeap         // receive buffer: out-of-order segments awaiting reordering

	acklist  []ackItem  // pending ACKs to be flushed
	nreqList []nreqItem // pending NREQ control segments (flushed with ACK phase)

	// clientSendNreq: schedule NREQ when a downstream PUSH arrives with sn > rcv_nxt.
	clientSendNreq bool
	// NREQ stall retry (client): while rcv_buf holds segments ahead of rcv_nxt, re-send NREQ on a timer.
	lastNreqScheduleMs  uint32
	nreqRetryBaseMs     uint32
	nreqRetryMaxMs      uint32
	nreqRetryCurMs      uint32
	nreqWireCopies      int    // duplicate NREQ frames per flush (lossy upstream DNS)
	nreqStallCapMs      uint32 // cap spacing for NREQ stall retries while rcv_buf has a hole (0=use backoff only)
	nreqIdleHeadAfterMs uint32 // after on-wire PUSH, NREQ if rcv_nxt still stale (0=disable); see maybeRetryNreqOnStall
	lastRcvNxtAdvanceMs uint32 // last time in-order receive advanced rcv_nxt
	lastSndPushOutMs    uint32 // last time flush encoded a PUSH onto the wire

	// onResendRequest: server-side handler for peer NREQ (runs under UDPSession.mu).
	onResendRequest func(firstMissingSN uint32, maxSegments uint32)
	// onOutboundPush: server-side snapshot of each sent PUSH payload (plaintext body only).
	onOutboundPush func(sn uint32, payload []byte)

	buffer []byte          // pre-allocated encoding buffer for flush()
	output output_callback // callback to write data to the underlying transport

	log logoutput_callback // trace log callback
}

type ackItem struct {
	sn uint32
	ts uint32
}

type nreqItem struct {
	first uint32
	count uint16
}

// NewKCP create a new kcp state machine
//
// 'conv' must be equal in the connection peers, or else data will be silently rejected.
//
// 'output' function will be called whenever these is data to be sent on wire.
func NewKCP(conv uint32, output output_callback) *KCP {
	kcp := new(KCP)
	kcp.conv = conv
	kcp.snd_wnd = IKCP_WND_SND
	kcp.rcv_wnd = IKCP_WND_RCV
	kcp.rmt_wnd = IKCP_WND_RCV
	kcp.mtu = IKCP_MTU_DEF
	kcp.mss = kcp.mtu - IKCP_OVERHEAD
	kcp.buffer = make([]byte, (kcp.mtu+IKCP_OVERHEAD)*3)
	kcp.rx_rto = IKCP_RTO_DEF
	kcp.rx_minrto = IKCP_RTO_MIN
	kcp.interval = IKCP_INTERVAL
	kcp.ts_flush = IKCP_INTERVAL
	kcp.ssthresh = IKCP_THRESH_INIT
	kcp.dead_link = IKCP_DEADLINK
	if s := os.Getenv("DNSTT_KCP_DEAD_LINK"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			const minDeadLink, maxDeadLink = 1, 500
			if n < minDeadLink {
				n = minDeadLink
			}
			if n > maxDeadLink {
				n = maxDeadLink
			}
			kcp.dead_link = uint32(n)
		}
	}
	kcp.output = output
	kcp.snd_buf = NewRingBuffer[segment](IKCP_WND_SND * 2)
	kcp.rcv_queue = NewRingBuffer[segment](IKCP_WND_RCV * 2)
	kcp.snd_queue = NewRingBuffer[segment](IKCP_WND_SND * 2)
	kcp.rcv_buf = newSegmentHeap()
	kcp.nreqRetryBaseMs, kcp.nreqRetryMaxMs = nreqRetryDurationsFromEnv()
	kcp.nreqRetryCurMs = kcp.nreqRetryBaseMs
	kcp.nreqWireCopies = nreqWireCopiesFromEnv()
	kcp.nreqStallCapMs = nreqStallCapMsFromEnv()
	kcp.nreqIdleHeadAfterMs = nreqIdleHeadAfterMsFromEnv()
	kcp.lastReplayMissFullSn = 0xFFFFFFFF
	return kcp
}

func nreqRetryDurationsFromEnv() (baseMs, maxMs uint32) {
	baseMs = 400
	maxMs = 8000
	if s := os.Getenv("DNSTT_KCP_NREQ_INTERVAL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			ms := uint32(d / time.Millisecond)
			if ms < 50 {
				ms = 50
			}
			if ms > 60000 {
				ms = 60000
			}
			baseMs = ms
		}
	}
	if s := os.Getenv("DNSTT_KCP_NREQ_INTERVAL_MAX"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			ms := uint32(d / time.Millisecond)
			if ms < baseMs {
				ms = baseMs
			}
			if ms > 120000 {
				ms = 120000
			}
			maxMs = ms
		}
	}
	return baseMs, maxMs
}

func nreqWireCopiesFromEnv() int {
	n := 2
	if s := os.Getenv("DNSTT_KCP_NREQ_COPIES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			n = v
		}
	}
	if n < 1 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	return n
}

// nreqStallCapMsFromEnv caps NREQ stall-retry spacing whenever rcv_buf holds segments ahead of rcv_nxt
// (any reorder hole, not only sn 0). 0 disables the cap (pure exponential backoff). Default 150ms.
// DNSTT_KCP_NREQ_STALL_CAP overrides DNSTT_KCP_NREQ_BOOTSTRAP_INTERVAL (same semantics, legacy name).
func nreqStallCapMsFromEnv() uint32 {
	if s := strings.TrimSpace(os.Getenv("DNSTT_KCP_NREQ_STALL_CAP")); s != "" {
		if ms, ok := parseNreqStallCapMs(s); ok {
			return ms
		}
	}
	if s := strings.TrimSpace(os.Getenv("DNSTT_KCP_NREQ_BOOTSTRAP_INTERVAL")); s != "" {
		if ms, ok := parseNreqStallCapMs(s); ok {
			return ms
		}
	}
	return 150
}

func parseNreqStallCapMs(s string) (ms uint32, ok bool) {
	ls := strings.ToLower(strings.TrimSpace(s))
	if ls == "0" || ls == "false" || ls == "off" {
		return 0, true
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		ms = uint32(d / time.Millisecond)
		if ms < 20 {
			ms = 20
		}
		if ms > 60000 {
			ms = 60000
		}
		return ms, true
	}
	return 0, false
}

// nreqIdleHeadAfterMsFromEnv: after sending PUSH, if rcv_nxt has not advanced for this long, emit NREQ
// for the next segment range (covers assume-delivered + lost first downstream byte, e.g. SOCKS dial ack).
// 0 disables. Default 250ms.
func nreqIdleHeadAfterMsFromEnv() uint32 {
	s := strings.TrimSpace(os.Getenv("DNSTT_KCP_NREQ_IDLE_HEAD"))
	if s == "" {
		return 250
	}
	ls := strings.ToLower(s)
	if ls == "0" || ls == "false" || ls == "off" {
		return 0
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		ms := uint32(d / time.Millisecond)
		if ms < 50 {
			ms = 50
		}
		if ms > 10000 {
			ms = 10000
		}
		return ms
	}
	return 250
}

// newSegment creates a KCP segment
func (kcp *KCP) newSegment(size int) (seg segment) {
	seg.data = defaultBufferPool.Get()[:size]
	return
}

// recycleSegment recycles a KCP segment
func (kcp *KCP) recycleSegment(seg *segment) {
	if seg.data != nil {
		defaultBufferPool.Put(seg.data)
		seg.data = nil
	}
}

// PeekSize checks the size of next message in the recv queue
func (kcp *KCP) PeekSize() (length int) {
	seg, ok := kcp.rcv_queue.Peek()
	if !ok {
		return -1
	}

	if seg.frg == 0 {
		return len(seg.data)
	}

	if kcp.rcv_queue.Len() < int(seg.frg+1) {
		return -1
	}

	for seg := range kcp.rcv_queue.ForEach {
		length += len(seg.data)
		if seg.frg == 0 {
			break
		}
	}
	return
}

// Receive data from kcp state machine
//
// Return number of bytes read.
//
// Return -1 when there is no readable data.
//
// Return -2 if len(buffer) is smaller than kcp.PeekSize().
func (kcp *KCP) Recv(buffer []byte) (n int) {
	peeksize := kcp.PeekSize()
	if peeksize < 0 {
		return -1
	}

	if peeksize > len(buffer) {
		return -2
	}

	var fast_recover bool
	if kcp.rcv_queue.Len() >= int(kcp.rcv_wnd) {
		fast_recover = true
	}

	// merge fragment
	for {
		seg, ok := kcp.rcv_queue.Pop()
		if !ok {
			break
		}

		copy(buffer, seg.data)
		buffer = buffer[len(seg.data):]
		n += len(seg.data)
		kcp.recycleSegment(&seg)
		if seg.frg == 0 {
			kcp.debugLog(IKCP_LOG_RECV, "stream", kcp.stream, "conv", kcp.conv, "sn", seg.sn, "ts", seg.ts, "datalen", n)
			break
		}
	}

	kcp.advanceRcvBufToQueue()

	// fast recover
	if kcp.rcv_queue.Len() < int(kcp.rcv_wnd) && fast_recover {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		kcp.probe |= IKCP_ASK_TELL
	}
	return
}

// Send is user/upper level send, returns below zero for error
func (kcp *KCP) Send(buffer []byte) int {
	var count int
	if len(buffer) == 0 {
		return -1
	}

	kcp.debugLog(IKCP_LOG_SEND, "stream", kcp.stream, "conv", kcp.conv, "datalen", len(buffer))

	// append to previous segment in streaming mode (if possible)
	if kcp.stream != 0 {
		if n := kcp.snd_queue.Len(); n > 0 {
			for seg := range kcp.snd_queue.ForEachReverse {
				if len(seg.data) < int(kcp.mss) {
					capacity := int(kcp.mss) - len(seg.data)
					extend := min(len(buffer), capacity)

					// grow slice, the underlying cap is guaranteed to
					// be larger than kcp.mss
					oldlen := len(seg.data)
					seg.data = seg.data[:oldlen+extend]
					copy(seg.data[oldlen:], buffer)
					buffer = buffer[extend:]
				}
				break
			}
		}

		if len(buffer) == 0 {
			return 0
		}
	}

	if len(buffer) <= int(kcp.mss) {
		count = 1
	} else {
		count = (len(buffer) + int(kcp.mss) - 1) / int(kcp.mss)
	}

	if count > 255 {
		return -2
	}

	if count == 0 {
		count = 1
	}
	if kcp.stream == 0 && count > 64 {
		return -1
	}

	for i := 0; i < count; i++ {
		var size int
		size = min(len(buffer), int(kcp.mss))
		seg := kcp.newSegment(size)
		copy(seg.data, buffer[:size])
		if kcp.stream == 0 { // message mode
			seg.frg = uint8(count - i - 1)
		} else { // stream mode
			seg.frg = 0
		}

		kcp.snd_queue.Push(seg)
		buffer = buffer[size:]
	}
	return 0
}

// update_ack updates the smoothed RTT and RTO based on a new RTT sample.
// Algorithm follows RFC 6298: Computing TCP's Retransmission Timer.
func (kcp *KCP) update_ack(rtt int32) {
	var rto uint32
	if kcp.rx_srtt == 0 {
		kcp.rx_srtt = rtt
		kcp.rx_rttvar = rtt >> 1
	} else {
		delta := rtt - kcp.rx_srtt
		kcp.rx_srtt += delta >> 3
		if delta < 0 {
			delta = -delta
		}
		if rtt < kcp.rx_srtt-kcp.rx_rttvar {
			// if the new RTT sample is below the bottom of the range of
			// what an RTT measurement is expected to be.
			// give an 8x reduced weight versus its normal weighting
			kcp.rx_rttvar += (delta - kcp.rx_rttvar) >> 5
		} else {
			kcp.rx_rttvar += (delta - kcp.rx_rttvar) >> 2
		}
	}
	rto = uint32(kcp.rx_srtt) + max(kcp.interval, uint32(kcp.rx_rttvar)<<2)
	kcp.rx_rto = min(max(kcp.rx_minrto, rto), IKCP_RTO_MAX)
}

// shrink_buf advances snd_una to the oldest unacknowledged segment in snd_buf.
func (kcp *KCP) shrink_buf() {
	if seg, ok := kcp.snd_buf.Peek(); ok {
		kcp.snd_una = seg.sn
	} else {
		kcp.snd_una = kcp.snd_nxt
	}
}

// parse_ack marks a segment as acknowledged in snd_buf by sequence number.
// The segment is not removed immediately; it stays until snd_una advances past it,
// avoiding expensive shifts in the ring buffer.
func (kcp *KCP) parse_ack(sn uint32) {
	if _itimediff(sn, kcp.snd_una) < 0 || _itimediff(sn, kcp.snd_nxt) >= 0 {
		return
	}

	for seg := range kcp.snd_buf.ForEach {
		if sn == seg.sn {
			// mark and free space, but leave the segment here,
			// and wait until `una` to delete this, then we don't
			// have to shift the segments behind forward,
			// which is an expensive operation for large window
			seg.acked = 1
			kcp.recycleSegment(seg)
			break
		}
		if _itimediff(sn, seg.sn) < 0 {
			break
		}
	}
}

// parse_fastack increments the fast-ack counter for segments with sn < the given sn.
// Returns 1 if any segment's fastack counter has reached the fast retransmit threshold.
func (kcp *KCP) parse_fastack(sn, ts uint32) int {
	shouldFastAck := 0
	if _itimediff(sn, kcp.snd_una) < 0 || _itimediff(sn, kcp.snd_nxt) >= 0 {
		return 0
	}

	for seg := range kcp.snd_buf.ForEach {
		if _itimediff(sn, seg.sn) < 0 {
			break
		} else if sn != seg.sn && _itimediff(seg.ts, ts) <= 0 {
			if seg.fastack != 0xFFFFFFFF {
				seg.fastack++
				if seg.fastack >= uint32(kcp.fastresend) {
					shouldFastAck = 1
				}
			}
		}
	}

	return shouldFastAck
}

// parse_una removes all segments from snd_buf that have been cumulatively acknowledged
// (i.e., segments with sn < una). Returns the number of segments removed.
func (kcp *KCP) parse_una(una uint32) int {
	count := 0
	for seg := range kcp.snd_buf.ForEach {
		if _itimediff(una, seg.sn) > 0 {
			kcp.recycleSegment(seg)
			count++
		} else {
			break
		}
	}
	kcp.snd_buf.Discard(count)
	return count
}

// discardFrontAcked removes contiguous acked segments from the front of snd_buf.
// Returns the number of discarded segments.
func (kcp *KCP) discardFrontAcked() int {
	count := 0
	for seg := range kcp.snd_buf.ForEach {
		if seg.acked == 1 {
			count++
		} else {
			break
		}
	}
	if count > 0 {
		kcp.snd_buf.Discard(count)
	}
	return count
}

// ack append
func (kcp *KCP) ack_push(sn, ts uint32) {
	kcp.acklist = append(kcp.acklist, ackItem{sn, ts})
}

// returns true if data has repeated
func (kcp *KCP) parse_data(newseg segment) bool {
	sn := newseg.sn
	if _itimediff(sn, kcp.rcv_nxt+kcp.rcv_wnd) >= 0 {
		atomic.AddUint64(&DefaultSnmp.RcvBeyondWindow, 1)
		if os.Getenv("DNSTT_KCP_RECV_GAP") != "" {
			log.Printf("kcp: recv beyond window conv=%08x rcv_nxt=%d rcv_wnd=%d got_sn=%d — segment dropped (too far ahead)",
				kcp.conv&0xFFFFFFFF, kcp.rcv_nxt, kcp.rcv_wnd, sn)
		}
		kcp.advanceRcvBufToQueue()
		return true
	}
	behind := _itimediff(sn, kcp.rcv_nxt) < 0

	repeat := false
	if !behind {
		if !kcp.rcv_buf.Has(sn) {
			// replicate the content if it's new
			dataCopy := defaultBufferPool.Get()[:len(newseg.data)]
			copy(dataCopy, newseg.data)
			newseg.data = dataCopy

			// insert the new segment into rcv_buf
			heap.Push(kcp.rcv_buf, newseg)
			if _itimediff(sn, kcp.rcv_nxt) > 0 {
				atomic.AddUint64(&DefaultSnmp.RcvReorderGap, 1)
				kcp.scheduleResendRequest(kcp.rcv_nxt, _itimediff(sn, kcp.rcv_nxt), true)
				if os.Getenv("DNSTT_KCP_RECV_GAP") != "" {
					verbose := os.Getenv("DNSTT_KCP_RECV_GAP_VERBOSE") != ""
					if verbose || !kcp.recvGapLogged {
						if !verbose {
							kcp.recvGapLogged = true
						}
						miss := _itimediff(sn, kcp.rcv_nxt)
						log.Printf("kcp: recv seq gap conv=%08x next_expected_sn=%d arrived_sn=%d missing_streak=%d payload=%d B rcv_buf_segs=%d — KCP sn [%d,%d) never arrived (inferred loss/reorder); smux/TCP blocked until sn %d; assume-delivered downstream may never resend",
							kcp.conv&0xFFFFFFFF, kcp.rcv_nxt, sn, miss, len(dataCopy), kcp.rcv_buf.Len(),
							kcp.rcv_nxt, sn, kcp.rcv_nxt)
					}
				}
			}
		} else {
			repeat = true
		}
	}

	kcp.advanceRcvBufToQueue()

	if behind {
		return true
	}
	return repeat
}

// advanceRcvBufToQueue moves contiguous segments from rcv_buf into rcv_queue.
func (kcp *KCP) advanceRcvBufToQueue() {
	for kcp.rcv_buf.Len() > 0 {
		seg := heap.Pop(kcp.rcv_buf).(segment)
		if seg.sn == kcp.rcv_nxt && kcp.rcv_queue.Len() < int(kcp.rcv_wnd) {
			kcp.rcv_queue.Push(seg)
			kcp.rcv_nxt++
			kcp.recvGapLogged = false
			kcp.resetNreqRetryAfterProgress()
		} else {
			heap.Push(kcp.rcv_buf, seg)
			break
		}
	}
}

// Input a packet into kcp state machine.
//
// 'regular' indicates it's a real data packet from remote, and it means it's not generated from ReedSolomon
// codecs.
//
// 'ackNoDelay' will trigger immediate ACK, but surely it will not be efficient in bandwidth
func (kcp *KCP) Input(data []byte, pktType PacketType, ackNoDelay bool) int {
	snd_una := kcp.snd_una
	if len(data) < IKCP_OVERHEAD {
		return -1
	}

	var latest uint32 // the latest ack packet
	var updateRTT int
	var inSegs uint64
	var flushSegments int // signal to flush segments

	for {
		if len(data) < int(IKCP_OVERHEAD) {
			break
		}

		conv16 := binary.LittleEndian.Uint16(data)
		if uint32(conv16) != (kcp.conv & 0xFFFF) {
			return -1
		}
		cmdFrg := data[2]
		cmd := (cmdFrg >> 6) + 81
		frg := cmdFrg & 0x3F
		wnd := uint16(data[3])
		ts := uint32(binary.LittleEndian.Uint16(data[4:6]))
		sn := uint32(binary.LittleEndian.Uint16(data[6:8]))
		una := uint32(binary.LittleEndian.Uint16(data[8:10]))
		length := uint32(binary.LittleEndian.Uint16(data[10:12]))
		data = data[IKCP_OVERHEAD:]

		conv := kcp.conv
		kcp.debugLog(IKCP_LOG_INPUT, "conv", conv, "cmd", cmd, "frg", frg, "wnd", wnd, "ts", ts, "sn", sn, "una", una, "len", length, "datalen", len(data))

		if len(data) < int(length) {
			return -2
		}

		if cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS && cmd != IKCP_CMD_NREQ &&
			cmd != IKCP_CMD_NMIS {
			return -3
		}

		// only trust window updates from regular packets. i.e: latest update
		if pktType == IKCP_PACKET_REGULAR {
			kcp.rmt_wnd = uint32(wnd)
		}
		// NREQ/NMIS reuse header fields; do not treat `una` as KCP cumulative ACK.
		if cmd != IKCP_CMD_NREQ && cmd != IKCP_CMD_NMIS {
			if kcp.parse_una(expandSN16(kcp.snd_una, una)) > 0 {
				flushSegments |= 1
			}
			kcp.shrink_buf()
		}

		switch cmd {
		case IKCP_CMD_ACK:
			sn = expandSN16(kcp.snd_una, sn)
			kcp.debugLog(IKCP_LOG_IN_ACK, "conv", conv, "sn", sn, "una", una, "ts", ts, "rto", kcp.rx_rto)
			kcp.parse_ack(sn)
			flushSegments |= kcp.parse_fastack(sn, ts)
			updateRTT |= 1
			latest = ts
		case IKCP_CMD_PUSH:
			sn = expandSN16(kcp.rcv_nxt, sn)
			repeat := true
			if _itimediff(sn, kcp.rcv_nxt+kcp.rcv_wnd) < 0 {
				if !kcp.suppressOutgoingACK {
					kcp.ack_push(sn, ts)
				}
				if _itimediff(sn, kcp.rcv_nxt) >= 0 {
					repeat = kcp.parse_data(segment{
						conv: conv, cmd: cmd, frg: frg, wnd: wnd,
						ts: ts, sn: sn, una: una,
						data: data[:length], // delayed data copying
					})
				}
			}
			if pktType == IKCP_PACKET_REGULAR && repeat {
				atomic.AddUint64(&DefaultSnmp.RepeatSegs, 1)
			}
			kcp.debugLog(IKCP_LOG_IN_PUSH, "conv", conv, "sn", sn, "una", una, "ts", ts, "packettype", pktType, "repeat", repeat)
		case IKCP_CMD_WASK:
			// ready to send back IKCP_CMD_WINS in Ikcp_flush
			// tell remote my window size
			kcp.probe |= IKCP_ASK_TELL
			kcp.debugLog(IKCP_LOG_IN_WASK, "conv", conv, "wnd", wnd, "ts", ts)
		case IKCP_CMD_WINS:
			kcp.debugLog(IKCP_LOG_IN_WINS, "conv", conv, "wnd", wnd, "ts", ts)
		case IKCP_CMD_NREQ:
			if length != 0 {
				return -2
			}
			cnt := una
			if cnt == 0 {
				cnt = 32
			}
			if cnt > maxNreqSegments {
				cnt = maxNreqSegments
			}
			if kcp.onResendRequest != nil {
				// sn is only 16 bits on the wire; the server resolves the full sequence number
				// against the replay map (see handleDownstreamNREQ / resolveWireSN).
				kcp.onResendRequest(sn, cnt)
			}
		case IKCP_CMD_NMIS:
			if length != 0 {
				return -2
			}
			fullSn := expandSN16(kcp.rcv_nxt, sn)
			now := currentMs()
			throttle := kcp.lastReplayMissFullSn == fullSn && kcp.lastReplayMissLogMs != 0 &&
				_itimediff(now, kcp.lastReplayMissLogMs) < 3000
			if !throttle {
				log.Printf("kcp: server replay miss conv=%08x missing_sn=%d — head segment not in server replay cache; NREQ cannot recover this gap",
					kcp.conv&0xFFFFFFFF, fullSn)
				kcp.lastReplayMissFullSn = fullSn
				kcp.lastReplayMissLogMs = now
			}
		default:
			return -3
		}

		inSegs++
		data = data[length:]
	}
	atomic.AddUint64(&DefaultSnmp.InSegs, inSegs)

	// update rtt with the latest ts
	// ignore the FEC packet
	if updateRTT != 0 && pktType == IKCP_PACKET_REGULAR {
		current := currentMs()
		if _itimediff(current, latest) >= 0 {
			kcp.update_ack(_itimediff(current, latest))
		}
	}

	// Congestion window (cwnd) update on ACK arrival.
	// Uses Reno-style algorithm: slow-start below ssthresh, then AIMD.
	if kcp.nocwnd == 0 {
		if _itimediff(kcp.snd_una, snd_una) > 0 {
			if kcp.cwnd < kcp.rmt_wnd {
				mss := kcp.mss
				if kcp.cwnd < kcp.ssthresh {
					kcp.cwnd++
					kcp.incr += mss
				} else {
					if kcp.incr < mss {
						kcp.incr = mss
					}
					kcp.incr += (mss*mss)/kcp.incr + (mss / 16)
					if (kcp.cwnd+1)*mss <= kcp.incr {
						if mss > 0 {
							kcp.cwnd = (kcp.incr + mss - 1) / mss
						} else {
							kcp.cwnd = kcp.incr + mss - 1
						}
					}
				}
				if kcp.cwnd > kcp.rmt_wnd {
					kcp.cwnd = kcp.rmt_wnd
					kcp.incr = kcp.rmt_wnd * mss
				}
			}
		}
	}

	// Determine if we need to flush data segments or acks
	if flushSegments != 0 {
		// If window has slided or, a fastack should be triggered,
		// Flush immediately. In previous implementations, we only
		// send out fastacks when interval timeouts, so the resending packets
		// have to wait until then. Now, we try to flush as soon as we can.
		kcp.flush(IKCP_FLUSH_FULL)
	} else if len(kcp.acklist) >= int(kcp.mtu/IKCP_OVERHEAD) { // clocking
		// This serves as the clock for low-latency network.(i.e. the latency is less than the interval.)
		// If the other end is waiting for confirmations, it has to want until the interval timeouts then
		// the flush() is triggered to send out the una & acks. In low-latency network, the interval time is too long to wait,
		// so acks have to be sent out immediately when there are too many.
		kcp.flush(IKCP_FLUSH_ACKONLY)
	} else if ackNoDelay && len(kcp.acklist) > 0 { // testing(xtaci): ack immediately if acNoDelay is set
		kcp.flush(IKCP_FLUSH_ACKONLY)
	} else if len(kcp.nreqList) > 0 {
		kcp.flush(IKCP_FLUSH_ACKONLY)
	}
	return 0
}

func (kcp *KCP) wnd_unused() uint16 {
	if kcp.rcv_queue.Len() < int(kcp.rcv_wnd) {
		return uint16(int(kcp.rcv_wnd) - kcp.rcv_queue.Len())
	}
	return 0
}

// flush sends pending data through the KCP output callback.
// This is the core scheduling function, organized in 6 phases:
//
//	Phase 1: Flush pending ACKs
//	Phase 2: Window probing (when remote window is zero)
//	Phase 3: Send window probe commands (WASK/WINS)
//	Phase 4: Move segments from snd_queue to snd_buf (sliding window)
//	Phase 5: Retransmit segments (initial, fast, early, RTO)
//	Phase 6: Update SNMP counters and congestion window
//
// Returns the suggested interval (ms) until the next flush call.
func (kcp *KCP) flush(flushType FlushType) (nextUpdate uint32) {
	var seg segment
	seg.conv = kcp.conv
	seg.cmd = IKCP_CMD_ACK
	seg.wnd = kcp.wnd_unused()
	seg.una = kcp.rcv_nxt

	buffer := kcp.buffer
	ptr := buffer

	// makeSpace makes room for writing
	makeSpace := func(space int) {
		size := len(buffer) - len(ptr)
		if size+space > int(kcp.mtu) {
			kcp.output(buffer, size)
			ptr = buffer
		}
	}

	// flush bytes in buffer if there is any
	flushBuffer := func() {
		size := len(buffer) - len(ptr)
		if size > 0 {
			kcp.output(buffer, size)
		}
	}

	defer func() {
		flushBuffer()
		atomic.StoreUint64(&DefaultSnmp.RingBufferSndQueue, uint64(kcp.snd_queue.Len()))
		atomic.StoreUint64(&DefaultSnmp.RingBufferRcvQueue, uint64(kcp.rcv_queue.Len()))
		atomic.StoreUint64(&DefaultSnmp.RingBufferSndBuffer, uint64(kcp.snd_buf.Len()))
	}()

	// --- Phase 1: Flush pending ACKs ---
	if flushType == IKCP_FLUSH_ACKONLY || flushType == IKCP_FLUSH_FULL {
		for i, ack := range kcp.acklist {
			makeSpace(IKCP_OVERHEAD)
			// filter jitters caused by bufferbloat
			if _itimediff(ack.sn, kcp.rcv_nxt) >= 0 || len(kcp.acklist)-1 == i {
				seg.sn, seg.ts = ack.sn, ack.ts
				ptr = seg.encode(ptr)
				kcp.debugLog(IKCP_LOG_OUT_ACK, "conv", seg.conv, "sn", seg.sn, "una", seg.una, "ts", seg.ts)
			}
		}
		kcp.acklist = kcp.acklist[0:0]

		copies := kcp.nreqWireCopies
		if copies < 1 {
			copies = 1
		}
		for _, nr := range kcp.nreqList {
			nseg := segment{
				conv: kcp.conv,
				cmd:  IKCP_CMD_NREQ,
				sn:   nr.first,
				ts:   0,
				una:  uint32(nr.count),
				wnd:  kcp.wnd_unused(),
			}
			for c := 0; c < copies; c++ {
				makeSpace(IKCP_OVERHEAD)
				ptr = nseg.encode(ptr)
			}
		}
		kcp.nreqList = kcp.nreqList[:0]
	}

	// --- Phase 2: Window probing (when remote window is zero) ---
	if kcp.rmt_wnd == 0 {
		current := currentMs()
		if kcp.probe_wait == 0 {
			kcp.probe_wait = IKCP_PROBE_INIT
			kcp.ts_probe = current + kcp.probe_wait
		} else {
			if _itimediff(current, kcp.ts_probe) >= 0 {
				if kcp.probe_wait < IKCP_PROBE_INIT {
					kcp.probe_wait = IKCP_PROBE_INIT
				}
				kcp.probe_wait += kcp.probe_wait / 2
				if kcp.probe_wait > IKCP_PROBE_LIMIT {
					kcp.probe_wait = IKCP_PROBE_LIMIT
				}
				kcp.ts_probe = current + kcp.probe_wait
				kcp.probe |= IKCP_ASK_SEND
			}
		}
	} else {
		kcp.ts_probe = 0
		kcp.probe_wait = 0
	}

	// --- Phase 3: Flush window probing commands ---
	if (kcp.probe & IKCP_ASK_SEND) != 0 {
		seg.cmd = IKCP_CMD_WASK
		makeSpace(IKCP_OVERHEAD)
		ptr = seg.encode(ptr)
		kcp.debugLog(IKCP_LOG_OUT_WASK, "conv", seg.conv, "wnd", seg.wnd, "ts", seg.ts)
	}

	// flush window probing commands
	if (kcp.probe & IKCP_ASK_TELL) != 0 {
		seg.cmd = IKCP_CMD_WINS
		makeSpace(IKCP_OVERHEAD)
		ptr = seg.encode(ptr)
		kcp.debugLog(IKCP_LOG_OUT_WINS, "conv", seg.conv, "wnd", seg.wnd, "ts", seg.ts)
	}

	kcp.probe = 0

	// --- Phase 4: Move segments from snd_queue to snd_buf (sliding window) ---
	// Effective window = min(snd_wnd, rmt_wnd, cwnd)
	cwnd := min(kcp.snd_wnd, kcp.rmt_wnd)
	if kcp.nocwnd == 0 {
		cwnd = min(kcp.cwnd, cwnd)
	}

	newSegsCount := 0
	for {
		if _itimediff(kcp.snd_nxt, kcp.snd_una+cwnd) >= 0 {
			break
		}

		newseg, ok := kcp.snd_queue.Pop()
		if !ok {
			break
		}

		newseg.conv = kcp.conv
		newseg.cmd = IKCP_CMD_PUSH
		newseg.sn = kcp.snd_nxt
		kcp.snd_buf.Push(newseg)
		kcp.snd_nxt++
		newSegsCount++
	}

	// calculate resent
	resent := uint32(kcp.fastresend)
	if kcp.fastresend <= 0 {
		resent = 0xffffffff
	}

	// --- Phase 5: Retransmit segments from snd_buf ---
	// Determines which segments need (re)transmission:
	// - Initial transmit (xmit == 0)
	// - Fast retransmit (fastack >= fastresend threshold)
	// - Early retransmit (fastack > 0, no new segments queued)
	// - RTO-based retransmit (current >= resendts)
	current := currentMs()
	var change, lostSegs, fastRetransSegs, earlyRetransSegs uint64
	nextUpdate = kcp.interval

	if flushType == IKCP_FLUSH_FULL {
		var dropFrontSegment bool
		for segment := range kcp.snd_buf.ForEach {
			needsend := false
			if segment.acked == 1 {
				continue
			}
			if segment.xmit == 0 { // initial transmit
				needsend = true
				segment.rto = kcp.rx_rto
				segment.resendts = current + segment.rto
			} else if segment.fastack >= resent && segment.fastack != 0xFFFFFFFF { // fast retransmit
				needsend = true
				segment.fastack = 0xFFFFFFFF // must wait until RTO to reset
				segment.rto = kcp.rx_rto
				segment.resendts = current + segment.rto
				change++
				fastRetransSegs++
			} else if segment.fastack > 0 && segment.fastack != 0xFFFFFFFF && newSegsCount == 0 { // early retransmit
				needsend = true
				segment.fastack = 0xFFFFFFFF
				segment.rto = kcp.rx_rto
				segment.resendts = current + segment.rto
				change++
				earlyRetransSegs++
			} else if _itimediff(current, segment.resendts) >= 0 { // RTO
				needsend = true
				if kcp.nodelay == 0 {
					segment.rto += kcp.rx_rto
				} else {
					segment.rto += kcp.rx_rto / 2
				}
				segment.fastack = 0
				segment.resendts = current + segment.rto
				lostSegs++
			}

			if needsend {
				current = currentMs()
				segment.xmit++
				segment.ts = current
				segment.wnd = seg.wnd
				segment.una = seg.una

				need := IKCP_OVERHEAD + len(segment.data)
				makeSpace(need)
				ptr = segment.encode(ptr)
				copy(ptr, segment.data)
				ptr = ptr[len(segment.data):]
				kcp.lastSndPushOutMs = current

				kcp.debugLog(IKCP_LOG_OUT_PUSH, "conv", segment.conv, "sn", segment.sn, "frg", segment.frg, "una", segment.una, "ts", segment.ts, "xmit", segment.xmit, "datalen", len(segment.data))

				if kcp.onOutboundPush != nil {
					pb := make([]byte, len(segment.data))
					copy(pb, segment.data)
					kcp.onOutboundPush(segment.sn, pb)
				}

				// After max retransmits without ACK, drop this segment only (do not close session).
				// Keeps session alive for high-latency/lossy networks and middleware with many clients.
				if segment.xmit >= kcp.dead_link {
					dropFrontSegment = true
				}
				// Optional lossy mode: as soon as we put a PUSH segment on wire once,
				// consider it delivered and stop waiting for peer ACKs.
				if kcp.assumeDeliveredAfterSend && segment.cmd == IKCP_CMD_PUSH {
					segment.acked = 1
					kcp.recycleSegment(segment)
				}
			}

			// get the nearest rto
			if rto := _itimediff(segment.resendts, current); rto > 0 && uint32(rto) < nextUpdate {
				nextUpdate = uint32(rto)
			}
		}
		if dropFrontSegment {
			if seg, ok := kcp.snd_buf.Pop(); ok {
				kcp.recycleSegment(&seg)
			}
			kcp.shrink_buf()
		}
		if kcp.assumeDeliveredAfterSend {
			if kcp.discardFrontAcked() > 0 {
				kcp.shrink_buf()
			}
		}
	}

	// --- Phase 6: Update SNMP counters and congestion window ---
	sum := lostSegs
	if lostSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.LostSegs, lostSegs)
	}
	if fastRetransSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.FastRetransSegs, fastRetransSegs)
		sum += fastRetransSegs
	}
	if earlyRetransSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.EarlyRetransSegs, earlyRetransSegs)
		sum += earlyRetransSegs
	}
	if sum > 0 {
		atomic.AddUint64(&DefaultSnmp.RetransSegs, sum)
	}

	// cwnd update
	if kcp.nocwnd == 0 {
		// Update ssthresh after fast retransmit.
		// Rate halving per RFC 6937: ssthresh = inflight / 2
		if change > 0 {
			inflight := kcp.snd_nxt - kcp.snd_una
			kcp.ssthresh = max(inflight/2, IKCP_THRESH_MIN)
			kcp.cwnd = kcp.ssthresh + resent
			kcp.incr = kcp.cwnd * kcp.mss
		}

		// Congestion control after RTO: reset cwnd per RFC 5681
		if lostSegs > 0 {
			kcp.ssthresh = max(cwnd/2, IKCP_THRESH_MIN)
			kcp.cwnd = 1
			kcp.incr = kcp.mss
		}

		if kcp.cwnd < 1 {
			kcp.cwnd = 1
			kcp.incr = kcp.mss
		}
	}

	return nextUpdate
}

// SetAssumeDeliveredAfterSend toggles sender behavior that drops PUSH segments
// from the send buffer right after first transmit, without waiting for ACKs.
func (kcp *KCP) SetAssumeDeliveredAfterSend(enable bool) {
	kcp.assumeDeliveredAfterSend = enable
}

// SetSuppressOutgoingACK toggles ACK emission for received PUSH segments.
// When enabled, this endpoint will not send KCP ACK packets.
func (kcp *KCP) SetSuppressOutgoingACK(enable bool) {
	kcp.suppressOutgoingACK = enable
}

// SetClientResendRequests enables sending IKCP_CMD_NREQ when a downstream seq gap is detected.
func (kcp *KCP) SetClientResendRequests(enable bool) {
	kcp.clientSendNreq = enable
}

// SetResendRequestHandler registers the server-side NREQ handler. firstMissingSN is the
// 16-bit-on-wire value from the NREQ header; the listener resolves it to a full sn via replay.
func (kcp *KCP) SetResendRequestHandler(h func(firstMissingSN uint32, maxSegments uint32)) {
	kcp.onResendRequest = h
}

// SetOutboundPushHook registers a callback invoked for each outbound PUSH payload (plaintext segment body).
func (kcp *KCP) SetOutboundPushHook(h func(sn uint32, payload []byte)) {
	kcp.onOutboundPush = h
}

// scheduleResendRequest queues an NREQ for [first, first+count). resetBackoff: gap first seen from
// parse_data (reset retry timer to base); false: timer-based retry (increase spacing).
func (kcp *KCP) scheduleResendRequest(first uint32, miss int32, resetBackoff bool) {
	if !kcp.clientSendNreq || miss <= 0 {
		return
	}
	n := uint16(miss)
	if n > maxNreqSegments {
		n = maxNreqSegments
	}
	for i := range kcp.nreqList {
		if kcp.nreqList[i].first == first {
			if n > kcp.nreqList[i].count {
				kcp.nreqList[i].count = n
			}
			kcp.markNreqScheduled(resetBackoff)
			return
		}
	}
	kcp.nreqList = append(kcp.nreqList, nreqItem{first: first, count: n})
	kcp.markNreqScheduled(resetBackoff)
}

func (kcp *KCP) markNreqScheduled(resetBackoff bool) {
	kcp.lastNreqScheduleMs = currentMs()
	if resetBackoff {
		kcp.nreqRetryCurMs = kcp.nreqRetryBaseMs
		return
	}
	next := kcp.nreqRetryCurMs * 2
	if next < kcp.nreqRetryCurMs {
		next = kcp.nreqRetryMaxMs
	}
	if next > kcp.nreqRetryMaxMs {
		next = kcp.nreqRetryMaxMs
	}
	kcp.nreqRetryCurMs = next
}

// maybeRetryNreqOnStall re-sends NREQ while out-of-order data is stuck in rcv_buf (client),
// or while waiting for the next in-order segment after we sent PUSH (idle head: lost segment with
// empty rcv_buf, e.g. SOCKS WriteAck under assume-delivered + suppress ACK path).
// Caller must hold UDPSession.mu.
func (kcp *KCP) maybeRetryNreqOnStall() {
	if !kcp.clientSendNreq {
		return
	}
	if len(kcp.nreqList) > 0 {
		return
	}
	now := currentMs()
	waitMs := kcp.nreqRetryCurMs
	if kcp.nreqStallCapMs > 0 && waitMs > kcp.nreqStallCapMs {
		waitMs = kcp.nreqStallCapMs
	}

	if kcp.rcv_buf.Len() > 0 {
		minSn, ok := kcp.rcv_buf.peekMinSN()
		if !ok {
			return
		}
		if _itimediff(minSn, kcp.rcv_nxt) <= 0 {
			return
		}
		if kcp.lastNreqScheduleMs != 0 {
			if _itimediff(now, kcp.lastNreqScheduleMs) < int32(waitMs) {
				return
			}
		}
		miss := _itimediff(minSn, kcp.rcv_nxt)
		if miss <= 0 {
			return
		}
		elapsed := int32(0)
		if kcp.lastNreqScheduleMs != 0 {
			elapsed = _itimediff(now, kcp.lastNreqScheduleMs)
		}
		kcp.scheduleResendRequest(kcp.rcv_nxt, miss, false)
		if os.Getenv("DNSTT_DEBUG") != "" {
			log.Printf("kcp: NREQ stall retry conv=%08x next_expected_sn=%d min_buf_sn=%d miss=%d after %dms (next gap %dms)",
				kcp.conv&0xFFFFFFFF, kcp.rcv_nxt, minSn, miss, elapsed, kcp.nreqRetryCurMs)
		}
		return
	}

	// Idle head: no out-of-order buffer, but we sent PUSH after last rcv_nxt advance and have nothing to read.
	if kcp.nreqIdleHeadAfterMs == 0 {
		return
	}
	if kcp.PeekSize() >= 0 {
		return
	}
	if kcp.lastSndPushOutMs == 0 || kcp.lastRcvNxtAdvanceMs == 0 {
		return
	}
	if _itimediff(kcp.lastSndPushOutMs, kcp.lastRcvNxtAdvanceMs) <= 0 {
		return
	}
	if _itimediff(now, kcp.lastSndPushOutMs) < int32(kcp.nreqIdleHeadAfterMs) {
		return
	}
	if kcp.lastNreqScheduleMs != 0 {
		if _itimediff(now, kcp.lastNreqScheduleMs) < int32(waitMs) {
			return
		}
	}
	miss := int32(32)
	if miss > maxNreqSegments {
		miss = maxNreqSegments
	}
	kcp.scheduleResendRequest(kcp.rcv_nxt, miss, false)
	if os.Getenv("DNSTT_DEBUG") != "" {
		log.Printf("kcp: NREQ idle-head retry conv=%08x rcv_nxt=%d (sent PUSH, no rcv_nxt progress for %dms after send)",
			kcp.conv&0xFFFFFFFF, kcp.rcv_nxt, _itimediff(now, kcp.lastSndPushOutMs))
	}
}

func (kcp *KCP) resetNreqRetryAfterProgress() {
	kcp.lastRcvNxtAdvanceMs = currentMs()
	kcp.lastReplayMissFullSn = 0xFFFFFFFF
	kcp.lastReplayMissLogMs = 0
	if !kcp.clientSendNreq {
		return
	}
	kcp.nreqRetryCurMs = kcp.nreqRetryBaseMs
}

// (deprecated)
//
// Update updates state (call it repeatedly, every 10ms-100ms), or you can ask
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec.
func (kcp *KCP) Update() {
	var slap int32

	current := currentMs()
	if kcp.updated == 0 {
		kcp.updated = 1
		kcp.ts_flush = current
	}

	slap = _itimediff(current, kcp.ts_flush)

	if slap >= 10000 || slap < -10000 {
		kcp.ts_flush = current
		slap = 0
	}

	if slap >= 0 {
		kcp.ts_flush += kcp.interval
		if _itimediff(current, kcp.ts_flush) >= 0 {
			kcp.ts_flush = current + kcp.interval
		}
		kcp.flush(IKCP_FLUSH_FULL)
	}
}

// (deprecated)
//
// Check determines when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to
// schedule ikcp_update (eg. implementing an epoll-like mechanism,
// or optimize ikcp_update when handling massive kcp connections)
func (kcp *KCP) Check() uint32 {
	current := currentMs()
	ts_flush := kcp.ts_flush
	tm_flush := int32(0x7fffffff)
	tm_packet := int32(0x7fffffff)
	minimal := uint32(0)
	if kcp.updated == 0 {
		return current
	}

	if _itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000 {
		ts_flush = current
	}

	if _itimediff(current, ts_flush) >= 0 {
		return current
	}

	tm_flush = _itimediff(ts_flush, current)

	for seg := range kcp.snd_buf.ForEach {
		diff := _itimediff(seg.resendts, current)
		if diff <= 0 {
			return current
		}
		if diff < tm_packet {
			tm_packet = diff
		}
	}

	minimal = uint32(tm_packet)
	if tm_packet >= tm_flush {
		minimal = uint32(tm_flush)
	}
	if minimal >= kcp.interval {
		minimal = kcp.interval
	}

	return current + minimal
}

// SetMtu changes MTU size, default is 1400.
func (kcp *KCP) SetMtu(mtu int) int {
	if mtu < int(IKCP_OVERHEAD)+1 {
		return -1
	}

	kcp.mtu = uint32(mtu)
	kcp.mss = kcp.mtu - IKCP_OVERHEAD
	kcp.buffer = make([]byte, (mtu+IKCP_OVERHEAD)*3)
	return 0
}

// NoDelay options
// fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
// nodelay: 0:disable(default), 1:enable
// interval: internal update timer interval in millisec, default is 100ms
// resend: 0:disable fast resend(default), 1:enable fast resend
// nc: 0:normal congestion control(default), 1:disable congestion control
func (kcp *KCP) NoDelay(nodelay, interval, resend, nc int) int {
	if nodelay >= 0 {
		kcp.nodelay = uint32(nodelay)
		if nodelay != 0 {
			kcp.rx_minrto = IKCP_RTO_NDL
		} else {
			kcp.rx_minrto = IKCP_RTO_MIN
		}
	}
	if interval >= 0 {
		if interval > 5000 {
			interval = 5000
		} else if interval < 10 {
			interval = 10
		}
		kcp.interval = uint32(interval)
	}
	if resend >= 0 {
		kcp.fastresend = int32(resend)
	}
	if nc >= 0 {
		kcp.nocwnd = int32(nc)
	}
	return 0
}

// WndSize sets maximum window size: sndwnd=32, rcvwnd=32 by default
func (kcp *KCP) WndSize(sndwnd, rcvwnd int) int {
	if sndwnd > 0 {
		kcp.snd_wnd = uint32(sndwnd)
	}
	if rcvwnd > 0 {
		kcp.rcv_wnd = uint32(rcvwnd)
	}
	return 0
}

// WaitSnd gets how many packet is waiting to be sent
func (kcp *KCP) WaitSnd() int {
	return kcp.snd_buf.Len() + kcp.snd_queue.Len()
}

// SetLogger configures the trace logger
func (kcp *KCP) SetLogger(mask KCPLogType, logger logoutput_callback) {
	if logger == nil {
		kcp.logmask = 0
		return
	}
	kcp.logmask = mask
	kcp.log = logger
}
