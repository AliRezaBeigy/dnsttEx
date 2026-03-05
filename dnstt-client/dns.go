package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"
)

	// EDNS option codes for tunnel payload (RFC 6891 private use).
	const (
	upstreamEDNSOptionCode   = 0xFF00 // client -> server payload
	downstreamEDNSOptionCode = 0xFF01 // server -> client payload
	)

	const (
	// How many bytes of random padding to insert into data-carrying queries.
	numPadding = 0
	// In an otherwise empty polling query, insert random padding to reduce cache hits.
	numPaddingForPoll = 8

	// sendLoop has a poll timer that automatically sends an empty polling
	// query when a certain amount of time has elapsed without a send. The
	// poll timer is initially set to initPollDelay. It increases by a
	// factor of pollDelayMultiplier every time the poll timer expires, up
	// to a maximum of maxPollDelay. The poll timer is reset to
	// initPollDelay whenever an a send occurs that is not the result of the
	// poll timer expiring.
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 2 * time.Second // was 10s; cap at 2s to limit stall on unstable DNS
	pollDelayMultiplier = 2.0

	// A limit on the number of empty poll requests we may send in a burst
	// as a result of receiving data.
	pollLimit = 16

	// Max raw payload bytes in one upstream EDNS option (ClientID + padding + packets).
	maxPayloadPerQuery = 512
	// Max bytes in a single tunnel packet (1-byte length prefix, values < 0xe0 are length).
	maxPacketSize = 223
)

// DNSPacketConn provides a packet-sending and -receiving interface over various
// forms of DNS. Upstream payload is carried in an EDNS option (binary, no encoding
// expansion); downstream payload is in the response EDNS option.
//
// DNSPacketConn does not handle the mechanics of actually sending and receiving
// encoded DNS messages. That is rather the responsibility of some other
// net.PacketConn such as net.UDPConn, HTTPPacketConn, or TLSPacketConn, one of
// which must be provided to NewDNSPacketConn.
//
// We don't have a need to match up a query and a response by ID. Queries and
// responses are vehicles for carrying data and for our purposes don't need to
// be correlated. When sending a query, we generate a random ID, and when
// receiving a response, we ignore the ID.
type DNSPacketConn struct {
	clientID turbotunnel.ClientID
	domain   dns.Name
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
// transport.WriteTo whenever a message needs to be sent.
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name) *DNSPacketConn {
	// Generate a new random ClientID.
	clientID := turbotunnel.NewClientID()
	c := &DNSPacketConn{
		clientID:        clientID,
		domain:          domain,
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

// dnsResponsePayload extracts the downstream payload from the response EDNS option.
// It returns nil if the message is not a valid NOERROR response or if our option is absent.
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
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			c.QueuePacketConn.QueueIncoming(p, addr)
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

// buildUpstreamPayload builds the raw option payload: ClientID(8) + padding byte + padding bytes + [1-byte len + packet]*.
func (c *DNSPacketConn) buildUpstreamPayload(packets [][]byte) []byte {
	var buf bytes.Buffer
	buf.Write(c.clientID[:])
	nPad := numPadding
	if len(packets) == 0 {
		nPad = numPaddingForPoll
	}
	buf.WriteByte(byte(224 + nPad))
	io.CopyN(&buf, rand.Reader, int64(nPad))
	for _, p := range packets {
		if len(p) >= 224 {
			continue // skip invalid
		}
		buf.WriteByte(byte(len(p)))
		buf.Write(p)
	}
	return buf.Bytes()
}

// send sends one or more packets in a single DNS query using an EDNS option (binary, no encoding expansion).
func (c *DNSPacketConn) send(transport net.PacketConn, packets [][]byte, addr net.Addr) error {
	payload := c.buildUpstreamPayload(packets)
	optData := dns.BuildEDNSOptions([]dns.EDNSOption{{Code: upstreamEDNSOptionCode, Data: payload}})
	// Minimal question name: one label "t" then domain (so server recognizes as tunnel).
	labels := append([][]byte{[]byte("t")}, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
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
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: optData},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}
	_, err = transport.WriteTo(buf, addr)
	return err
}

// sendLoop takes packets from the outgoing queue, batches them up to maxPayloadPerQuery,
// and sends them in one query per batch. Also sends empty polling queries when idle.
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) error {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	overhead := 8 + 1 + numPadding // ClientID + padding byte + padding bytes for data query
	payloadLimit := maxPayloadPerQuery - overhead
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
			select { case <-c.pollChan: default: }
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
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		if err := c.send(transport, packets, addr); err != nil {
			log.Printf("send: %v", err)
		}
	}
}
