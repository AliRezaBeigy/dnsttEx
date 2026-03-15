// DNS send path: build query wire, upstream payload, send and sendLoop.
// See dns.go for DNSPacketConn and package documentation.

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"dnsttEx/dns"
)

// Probe mode bytes (first byte of payload after clientID).
const (
	probeModePoll     = 0    // normal idle poll
	probeModeHintPoll = 0xFE // poll with 2-byte max-response-size hint (survives OPT Class rewriting by resolvers)
	probeModePING     = 0xFF // health-check PING; server must respond with PONG
)

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

// buildUpstreamPayload builds raw payload with compact framing. See dns.go comment.
func (c *DNSPacketConn) buildUpstreamPayload(packets [][]byte, maxRespHint int) []byte {
	var buf bytes.Buffer
	buf.Write(c.clientID[:])
	if len(packets) == 0 {
		if maxRespHint > 0 && maxRespHint <= 0xFFFF {
			buf.WriteByte(probeModeHintPoll)
			buf.WriteByte(byte(maxRespHint >> 8))
			buf.WriteByte(byte(maxRespHint))
		} else {
			buf.WriteByte(0)
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

// send encodes payload in the question name and writes one DNS query. See dns.go.
func (c *DNSPacketConn) send(transport net.PacketConn, packets [][]byte, addr net.Addr, maxRespOverride, maxReqOverride int) error {
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
		sendAnyway := len(packets) == 0 && len(decoded) <= 11+probeNoiseLen
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

// sendLoop batches packets into the question name and sends polling queries when idle. See dns.go for full doc.
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
	var lastTunnelSend time.Time
	for {
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

		var packets [][]byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		unstash := c.QueuePacketConn.Unstash(addr)
		pollTimerExpired := false

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
