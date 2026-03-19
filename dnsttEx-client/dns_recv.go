// DNS receive path: parse responses, extract payload, queue packets.
// See dns.go for DNSPacketConn and package documentation.

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"

	"dnsttEx/dns"
)

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
			return nil, err
		}
		p := make([]byte, n)
		_, err = io.ReadFull(r, p)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return p, err
	}
}

// recvLoop repeatedly calls transport.ReadFrom to receive a DNS message,
// extracts its payload and breaks it into packets, and stores the packets in a
// queue to be returned from a future call to c.ReadFrom. See dns.go for full doc.
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

		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("MessageFromWireFormat: %v", err)
			continue
		}
		c.statsResponsesRecvTotal.Add(1)

		if c.inFlightCap > 0 {
			if cur := c.inFlightCount.Load(); cur > 0 {
				c.inFlightCount.Add(-1)
			}
			select {
			case c.inFlightSignal <- struct{}{}:
			default:
			}
		}

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
			if c.maxResponseSize > 256 {
				newMax := c.maxResponseSize * 3 / 4
				if newMax < 256 {
					newMax = 256
				}
				c.maxResponseSize = newMax
				log.Printf("Reduced max response size to %d bytes due to truncation", newMax)
			}
			for i := 0; i < 2; i++ {
				select {
				case c.pollChan <- struct{}{}:
				default:
				}
			}
		}

		rcode := resp.Flags & 0x000f

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

		if rcode != dns.RcodeNoError {
			qName := ""
			if len(resp.Question) >= 1 {
				qName = resp.Question[0].Name.String()
			}
			rcodeStr := "error"
			if rcode == dns.RcodeNameError {
				rcodeStr = "NXDOMAIN (No such name)"
			}
			log.Printf("DNS response %s (rcode %d) for query %s — treating like timeout", rcodeStr, rcode, qName)
			continue
		}

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
		if bytes.Equal(payload, ProbeResponsePONG) {
			if dnsttLogRxData() {
				log.Printf("DNSTT_RX_POLL_EMPTY ← from %s | PONG only (health / idle)", addr)
			}
			continue
		}

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
		if any {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}
