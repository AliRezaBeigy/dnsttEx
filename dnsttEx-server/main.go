// dnstt-server is the server end of a DNS tunnel.
//
// Usage:
//
//	dnstt-server -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
//	dnstt-server -udp ADDR [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] [-fallback FALLBACKADDR] DOMAIN UPSTREAMADDR
//
// Example:
//
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//	dnstt-server -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000
//
// With fallback for non-DNS traffic:
//
//	dnstt-server -udp :53 -privkey-file server.key -fallback 127.0.0.1:8888 t.example.com 127.0.0.1:8000
//
// To generate a persistent server private key, first run with the -gen-key
// option. By default the generated private and public keys are printed to
// standard output. To save them to files instead, use the -privkey-file and
// -pubkey-file options.
//
//	dnstt-server -gen-key
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//
// You can give the server's private key as a file or as a hex string.
//
//	-privkey-file server.key
//	-privkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//
// The -udp option controls the address that will listen for incoming DNS
// queries.
//
// The -mtu option controls the maximum size of response UDP payloads.
// Queries that do not advertise requester support for responses of at least
// this size at least this size will be responded to with a FORMERR. The default
// value is maxUDPPayload.
//
// The -fallback option specifies a UDP address (host:port). If an incoming
// packet is not a valid DNS message, it will be forwarded to this address.
// This acts as a simple UDP proxy for non-DNS traffic, allowing another
// service to run on the same port.
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// UPSTREAMADDR is the TCP address to which incoming tunnelled streams will be
// forwarded.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"dnsttEx/dns"
	"dnsttEx/internal/kcp"
	"dnsttEx/noise"
	"dnsttEx/turbotunnel"

	"github.com/jellydator/ttlcache/v3"
	"github.com/xtaci/smux"
)

const (
	upstreamEDNSOptionCode   = 0xFF00
	downstreamEDNSOptionCode = 0xFF01
	probeModeSizedFrame      = 0xFD
	// Health-check probe: client sends payload with mode byte 0xFF (PING), server responds with "PONG".
	probeModePING = 0xFF
)

const (
	// smux streams will be closed after this much time without receiving data.
	idleTimeout = 2 * time.Minute

	// How to set the TTL field in Answer resource records.
	responseTTL = 60

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second

	// How long a fallback session can be idle before being torn down.
	fallbackIdleTimeout = 2 * time.Minute
)

var (
	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// Tuned for DNS chains with high intermediate latency (e.g. .ir TLD),
	// where root→TLD→NS hops can consume 200-500ms of a resolver's ~2s
	// timeout budget. Override at runtime with DNSTT_RESPONSE_DELAY (e.g. "200ms").
	maxResponseDelay = 200 * time.Millisecond
)

// clientState holds per-client metadata that must survive across queries but
// should be evicted when the client goes idle. Stored in a TTL cache keyed by
// ClientID so memory is bounded under high client churn.
type clientState struct {
	mu sync.Mutex // serializes data collection in sendLoop (TryLock)
}

var (
	// maxUDPPayload is the maximum DNS response size we send.
	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 1280 is the minimum IPv6 MTU, 40 bytes
	// is the size of an IPv6 header (though without any extension headers),
	// and 8 bytes is the size of a UDP header.
	//
	// Control this value with the -mtu command-line option.
	//
	// https://dnsflagday.net/2020/#message-size-considerations
	// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly
	// all current networks."
	//
	// On 2020-04-19, the Quad9 resolver was seen to have a UDP payload size
	// of 1232. Cloudflare's was 1452, and Google's was 4096.
	maxUDPPayload = 1280 - 40 - 8

	// minSupportedResponseSize is the smallest DNS response size we support
	// (worst-case 255-octet name). KCP segment size is capped so one segment
	// plus length prefix fits in this. 256 is too small for worst-case name.
	minSupportedResponseSize = 512
)

// Base36 (0-9a-v, 5 bits/symbol); decode is case-insensitive for QNAME randomization.
const base36Alphabet = "0123456789abcdefghijklmnopqrstuv"

func base36DecodedLen(n int) int { return n * 5 / 8 }

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

var errBase36Decode = errors.New("invalid base36")

// generateKeypair generates a private key and the corresponding public key. If
// privkeyFilename and pubkeyFilename are respectively empty, it prints the
// corresponding key to standard output; otherwise it saves the key to the given
// file name. The private key is saved with mode 0400 and the public key is
// saved with 0666 (before umask). In case of any error, it attempts to delete
// any files it has created before returning.
func generateKeypair(privkeyFilename, pubkeyFilename string) (err error) {
	// Filenames to delete in case of error (avoid leaving partially written
	// files).
	var toDelete []string
	defer func() {
		for _, filename := range toDelete {
			fmt.Fprintf(os.Stderr, "deleting partially written file %s\n", filename)
			if closeErr := os.Remove(filename); closeErr != nil {
				fmt.Fprintf(os.Stderr, "cannot remove %s: %v\n", filename, closeErr)
				if err == nil {
					err = closeErr
				}
			}
		}
	}()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)

	if privkeyFilename != "" {
		// Save the privkey to a file.
		f, err := os.OpenFile(privkeyFilename, os.O_RDWR|os.O_CREATE, 0400)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, privkeyFilename)
		err = noise.WriteKey(f, privkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	if pubkeyFilename != "" {
		// Save the pubkey to a file.
		f, err := os.Create(pubkeyFilename)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, pubkeyFilename)
		err = noise.WriteKey(f, pubkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	// All good, allow the written files to remain.
	toDelete = nil

	if privkeyFilename != "" {
		fmt.Printf("privkey written to %s\n", privkeyFilename)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubkeyFilename != "" {
		fmt.Printf("pubkey  written to %s\n", pubkeyFilename)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}

	return nil
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// handleStream bidirectionally connects a client stream with a TCP socket
// addressed by upstream.
func handleStream(stream *smux.Stream, upstream string, conv uint32) error {
	dialer := net.Dialer{
		Timeout: upstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer upstreamConn.Close()
	upstreamTCPConn := upstreamConn.(*net.TCPConn)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, upstreamTCPConn)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←upstream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy upstream←stream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session,
// then awaits smux streams. In tcp tunnel mode each stream is relayed to upstream;
// in socks mode the client sends destination per stream (tunnelproto).
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string, socksTunnel bool) error {
	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	// Put an smux session on top of the encrypted Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = 15 * time.Second // send PING every 15s
	smuxConfig.KeepAliveTimeout = 30 * time.Second  // declare dead after 30s (was idleTimeout=2min)
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024    // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Printf("begin stream %08x:%d", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("end stream %08x:%d", conn.GetConv(), stream.ID())
				stream.Close()
			}()
			if socksTunnel {
				handleSocksRelay(stream, conn.GetConv())
			} else {
				err := handleStream(stream, upstream, conn.GetConv())
				if err != nil {
					log.Printf("stream %08x:%d handleStream: %v", conn.GetConv(), stream.ID(), err)
				}
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string, socksTunnel bool) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Printf("begin session %08x", conn.GetConv())
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Disable the dynamic congestion window (limit only by the
		// maximum of local and remote static windows). Use nodelay=1
		// and resend=2 for fast retransmit on the high-latency,
		// potentially lossy DNS transport.
		conn.SetNoDelay(
			1,  // nodelay=1: flush immediately, no Nagle-like coalescing delay
			20, // interval=20ms: KCP update tick (0 causes edge-case behavior in kcp-go)
			2,  // resend=2: fast retransmit after 2 ACK gaps (0 = disabled)
			1,  // nc=1: congestion window off
		)
		conn.SetWindowSize(512, 512) // was QueueSize/2=64; larger window for high-latency DNS
		// Custom mode: do not wait for client ACK for sent KCP PUSH segments.
		// Once placed on wire, sender considers segment delivered (no retransmit).
		conn.SetAssumeDeliveredAfterSend(true)
		if rc := conn.SetMtu(mtu); !rc {
			panic(rc)
		}
		go func() {
			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				conn.Close()
			}()
			err := acceptStreams(conn, privkey, upstream, socksTunnel)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x acceptStreams: %v", conn.GetConv(), err)
			}
		}()
	}
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding. It
// returns a nil error only when a packet was read successfully. It returns
// io.EOF only when there were 0 bytes remaining to read from r. It returns
// io.ErrUnexpectedEOF when EOF occurs in the middle of an encoded packet.
//
// The prefixing scheme is as follows. A length prefix L < 0xe0 means a data
// packet of L bytes. A length prefix L >= 0xe0 means padding of L - 0xe0 bytes
// (not counting the length of the length prefix itself).
func nextPacket(r *bytes.Reader) ([]byte, error) {
	// Convert io.EOF to io.ErrUnexpectedEOF.
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(ioutil.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// responseFor constructs a response dns.Message that is appropriate for query.
// It returns (resp, payload, maxResponseSize). If resp is nil, no response is sent.
// If resp has RcodeNoError, payload is the decoded tunnel data and maxResponseSize
// is the maximum UDP response size for this request (min of requester's EDNS size and server -mtu).
func responseFor(query *dns.Message, domain dns.Name) (*dns.Message, []byte, int) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, nil, 0
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requester.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requester does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil, maxUDPPayload
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil, maxUDPPayload
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		// https://tools.ietf.org/html/rfc6891#section-6.1.1 "Values
		// lower than 512 MUST be treated as equal to 512."
		payloadSize = 512
	}
	// Cap response size by requester's limit and server -mtu; don't reject 512-only resolvers.
	effectiveMaxResponse := payloadSize
	if effectiveMaxResponse > maxUDPPayload {
		effectiveMaxResponse = maxUDPPayload
	}

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil, effectiveMaxResponse
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: not authoritative for %s (query name not under domain)", question.Name)
		return resp, nil, effectiveMaxResponse
	}
	resp.Flags |= 0x0400 // AA = 1

	// QNAME minimization (RFC 7816/RFC 9156): resolvers may send only the zone name
	// (e.g. mnm.e.example.come) to discover authority, then send the full name. If we
	// return NXDOMAIN for the zone apex, the resolver may give up. Return NOERROR
	// with no payload so the resolver continues (e.g. retries with full name).
	if len(prefix) == 0 {
		return resp, nil, effectiveMaxResponse
	}

	if query.Opcode() != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil, effectiveMaxResponse
	}

	// Resolvers may probe with A/AAAA (QTYPE minimization) or send minimized QNAME; return NOERROR
	// with no answer so they retry with TXT or full name instead of giving up with NXDOMAIN.
	if question.Type != dns.RRTypeTXT {
		return resp, nil, effectiveMaxResponse
	}

	// Payload: prefer EDNS option 0xFF00 (when resolver forwards it); else decode from question name (works with 8.8.8.8 etc).
	var payload []byte
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		opts, err := dns.ParseEDNSOptions(rr.Data)
		if err != nil {
			continue
		}
		payload = dns.FindEDNSOption(opts, upstreamEDNSOptionCode)
		break
	}
	if len(payload) < 9 {
		// Fallback: payload in question name (Base36). Decode is case-insensitive for QNAME randomization (e.g. 8.8.8.8).
		encoded := bytes.Join(prefix, nil)
		decoded := make([]byte, base36DecodedLen(len(encoded)))
		if err := base36Decode(decoded, encoded); err != nil {
			// Minimized QNAME (e.g. 68a.e.markop.ir): resolver sent partial name; return NOERROR so it retries with full name.
			return resp, nil, effectiveMaxResponse
		}
		payload = decoded
	}
	if len(payload) < 9 {
		// Short prefix / minimized QNAME: not enough for ClientID+mode; return NOERROR so resolver retries with full name.
		return resp, nil, effectiveMaxResponse
	}

	return resp, payload, effectiveMaxResponse
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
// recvLoop sends instances of record to sendLoop via a channel. sendLoop
// receives instances of record and may fill in the message's Answer section
// before sending it.
type record struct {
	Resp            *dns.Message
	Addr            net.Addr
	ClientID        turbotunnel.ClientID
	MaxResponseSize int  // max UDP response size for this request (min of requester EDNS and server -mtu)
	PongResponse    bool // true: health-check PING; send payload "PONG" or PongPayloadSize bytes
	PongPayloadSize int  // when > 0, response payload is this many bytes (for MTU discovery); else literal "PONG"
}

// dequeueOneDownstreamNonBlocking attempts a zero-wait read from per-client
// unstash first, then outgoing queue. It returns (packet, true) on success.
func dequeueOneDownstreamNonBlocking(ttConn *turbotunnel.QueuePacketConn, clientID turbotunnel.ClientID) ([]byte, bool) {
	unstash := ttConn.Unstash(clientID)
	select {
	case p := <-unstash:
		return p, true
	default:
	}
	outgoing := ttConn.OutgoingQueue(clientID)
	select {
	case p := <-outgoing:
		return p, true
	default:
	}
	return nil, false
}

// stashDownstreamWithBackpressure stores packet in per-client stash without loss.
// In high-burst mode we prefer backpressure over silent drops.
func stashDownstreamWithBackpressure(ttConn *turbotunnel.QueuePacketConn, clientID turbotunnel.ClientID, p []byte) {
	for !ttConn.Stash(p, clientID) {
		time.Sleep(1 * time.Millisecond)
	}
}

// --- Fallback NAT logic for non-DNS packets ---

// UDPAddrKey is a comparable struct that can be used as a map key to represent
// a net.UDPAddr. It's designed to be highly performant by avoiding allocations.
//
// A net.UDPAddr cannot be a map key directly because its IP field is a slice,
// and slices are not comparable in Go. We solve this by converting the IP
// slice to a fixed-size [16]byte array, which is comparable. A 16-byte
// array can hold both IPv4 and IPv6 addresses.
type UDPAddrKey struct {
	IP   [16]byte
	Port int
	Zone string // For IPv6 link-local addresses
}

// NewAddrKey converts a *net.UDPAddr into a comparable UDPAddrKey.
// This function is designed to be allocation-free.
func NewAddrKey(addr *net.UDPAddr) UDPAddrKey {
	var key UDPAddrKey
	// The IP field in UDPAddr is a slice. We copy its contents into a
	// fixed-size 16-byte array. The IP.To16() method ensures that the
	// IP is in a 16-byte format, suitable for both IPv4 and IPv6.
	// This copy is the key to making the struct comparable.
	copy(key.IP[:], addr.IP.To16())
	key.Port = addr.Port
	key.Zone = addr.Zone
	return key
}

// FallbackManager handles forwarding of non-DNS UDP packets using a TTL cache
// to manage client sessions.
type FallbackManager struct {
	sessions     *ttlcache.Cache[UDPAddrKey, net.PacketConn]
	mainConn     net.PacketConn
	fallbackAddr net.Addr
}

// NewFallbackManager creates a new manager for forwarding non-DNS packets.
func NewFallbackManager(mainConn net.PacketConn, fallbackAddr net.Addr) *FallbackManager {
	log.Printf("non-DNS packets will be forwarded to %s", fallbackAddr)

	cache := ttlcache.New(ttlcache.WithTTL[UDPAddrKey, net.PacketConn](fallbackIdleTimeout))
	cache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, i *ttlcache.Item[UDPAddrKey, net.PacketConn]) {
		// This function is called when a client session expires due to inactivity.
		// Closing the connection will cause the corresponding forwardReplies goroutine to exit.
		i.Value().Close()
	})

	// Start a goroutine to clean up expired items from the cache periodically.
	go cache.Start()

	return &FallbackManager{
		sessions:     cache,
		mainConn:     mainConn,
		fallbackAddr: fallbackAddr,
	}
}

// HandlePacket finds or creates a fallback session for the given client address
// and forwards the packet to the fallback server. Activity on a session (i.e.,
// a call to this function) refreshes its timeout.
func (m *FallbackManager) HandlePacket(packet []byte, clientAddr net.Addr) {
	clientKey := NewAddrKey(clientAddr.(*net.UDPAddr))

	// Get the session from the cache. This also refreshes the TTL.
	item := m.sessions.Get(clientKey)
	var proxyConn net.PacketConn

	if item == nil {
		// Session doesn't exist, create a new one.
		newConn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			log.Printf("failed to create fallback socket for %v: %v", clientKey, err)
			return
		}
		proxyConn = newConn // Use the new connection

		// Add the new session to the cache.
		// The TTL is set to the default defined in the cache constructor.
		m.sessions.Set(clientKey, newConn, ttlcache.DefaultTTL)
		log.Printf("created new fallback session for %s via %s", clientAddr.String(), newConn.LocalAddr())

		// Start a goroutine to forward replies for this new session.
		go m.forwardReplies(newConn, clientAddr)

	} else {
		// Session exists, use the existing connection.
		proxyConn = item.Value()
	}

	// Forward the client's packet to the fallback address.
	_, err := proxyConn.WriteTo(packet, m.fallbackAddr)
	if err != nil {
		log.Printf("fallback write to %s for client %v failed: %v", m.fallbackAddr, clientKey, err)
	}
}

// forwardReplies reads from a session's proxy connection (which receives packets
// from the fallback server) and forwards them to the original client via the
// main server connection. This method runs in its own goroutine for each session
// and exits when the proxy connection is closed by the cache's eviction handler.
func (m *FallbackManager) forwardReplies(proxyConn net.PacketConn, clientAddr net.Addr) {
	defer log.Printf("ending fallback reply forwarder for %s", clientAddr.String())

	buf := make([]byte, 65535) // max UDP packet size
	for {
		n, _, err := proxyConn.ReadFrom(buf)
		if err != nil {
			// Error is expected when the connection is closed by the eviction handler.
			// net.ErrClosed is the specific error returned in this case.
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("fallback read from proxy conn for %s failed: %v", clientAddr, err)
			}
			return // Exit goroutine.
		}

		// Got a reply from the fallback server. Forward it to the original client.
		_, writeErr := m.mainConn.WriteTo(buf[:n], clientAddr)
		if writeErr != nil {
			log.Printf("fallback write to client %s failed: %v", clientAddr, writeErr)
			// If we can't write to the client, we don't need to do anything special.
			// The session will eventually time out and be cleaned up if the client
			// stops sending packets.
		}
	}
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts them on ttConn's incoming queue. Whenever
// a query calls for a response, constructs a partial response and passes it to
// sendLoop over ch. Invalid DNS packets are passed to the FallbackManager.
func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record, fallbackMgr *FallbackManager) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}
		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			if fallbackMgr != nil {
				// Packet is not a valid DNS message, forward it if fallback is configured.
				fallbackMgr.HandlePacket(buf[:n], addr)
			} else {
				log.Printf("cannot parse DNS query from %s: %v", addr, err)
			}
			continue
		}

		resp, payload, maxRespSize := responseFor(&query, domain)
		// Extract the ClientID from the payload.
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		body := payload[n:]
		if n == len(clientID) && len(body) >= 1 {
			first := body[0]
			if first == probeModePING {
				// Health-check PING: respond with PONG, or with N bytes of padding for MTU discovery.
				// Only treat body[1:3] as requested size when it's an MTU probe (BuildMTUProbeMessage:
				// client sends 2 size bytes + 6 noise = 9 bytes body total). Simple PING (scan/health)
				// has body = 7 bytes (6 noise). Request-size probe (BuildProbeMessageWithRequestSize)
				// has body = 7 + padding (55, 103, ...); body[1:3] there is noise, not size.
				pongSize := 0
				if len(body) == 9 {
					pongSize = int(body[1])<<8 | int(body[2])
					if pongSize > maxRespSize {
						pongSize = maxRespSize
					}
					if pongSize > maxUDPPayload {
						pongSize = maxUDPPayload
					}
				}
				if resp != nil {
					select {
					case ch <- &record{Resp: resp, Addr: addr, ClientID: clientID, MaxResponseSize: maxRespSize, PongResponse: true, PongPayloadSize: pongSize}:
					default:
						log.Printf("sendLoop channel full, dropping PONG response")
					}
				}
				if pongSize > 0 && os.Getenv("DNSTT_DEBUG") != "" {
					log.Printf("DNSTT_DEBUG: MTU probe received, will send PONG %d bytes", pongSize)
				}
				continue
			}
			// In-band response-size hint is carried per query:
			// [0xFD][hint_hi][hint_lo][frame...]
			// frame: 0=poll, 1..223=single packet length, 224+=legacy packed.
			if first == probeModeSizedFrame && len(body) >= 4 {
				hint := int(body[1])<<8 | int(body[2])
				if hint >= 512 && hint < maxRespSize {
					maxRespSize = hint
				}
				frame := body[3:]
				frameFirst := frame[0]
				if frameFirst == 0 {
					// Poll: no packets
				} else if frameFirst >= 1 && frameFirst < 224 {
					// Single packet of length frameFirst
					if len(frame) >= 1+int(frameFirst) {
						p := frame[1 : 1+frameFirst]
						ttConn.QueueIncoming(p, clientID)
					}
				} else {
					// Legacy: padding byte + padding bytes + [len+packet]*
					r := bytes.NewReader(frame)
					for {
						p, err := nextPacket(r)
						if err != nil {
							break
						}
						ttConn.QueueIncoming(p, clientID)
					}
				}
			} else if first == 0 {
				// Backward-compat poll: no packets.
			} else if first >= 1 && first < 224 {
				// Backward-compat single packet of length first.
				if len(body) >= 1+int(first) {
					p := body[1 : 1+first]
					ttConn.QueueIncoming(p, clientID)
				}
			} else {
				// Backward-compat legacy: padding byte + padding bytes + [len+packet]*.
				r := bytes.NewReader(body)
				for {
					p, err := nextPacket(r)
					if err != nil {
						break
					}
					ttConn.QueueIncoming(p, clientID)
				}
			}
		} else {
			// Payload too short (no full ClientID) or no mode byte (8 bytes only).
			// When payload is nil we may have returned NOERROR for zone-apex / QNAME-minimized query; do not overwrite.
			if payload != nil && resp != nil && resp.Rcode() == dns.RcodeNoError {
				resp.Flags |= dns.RcodeNameError
				log.Printf("NXDOMAIN: payload too short for ClientID+mode (payload %d bytes) query %s", len(payload), query.Question[0].Name)
			}
		}
		// If a response is called for, pass it to sendLoop via the channel.
		if resp != nil {
			select {
			case ch <- &record{Resp: resp, Addr: addr, ClientID: clientID, MaxResponseSize: maxRespSize}:
			default:
				// sendLoop is busy; drop this response opportunity.
				// The client will retry after its poll timer fires.
				log.Printf("sendLoop channel full, dropping response for %s", clientID)
			}
		}
	}
}

// sendLoop repeatedly receives records from ch. Those that represent an error
// response, it sends on the network immediately. Those that represent a
// response capable of carrying data, it packs full of as many packets as will
// fit while keeping the total size under maxEncodedPayload, then sends it.
func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record, maxEncodedPayload int, clientCache *ttlcache.Cache[turbotunnel.ClientID, *clientState]) error {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			maxSize := rec.MaxResponseSize
			if maxSize <= 0 {
				maxSize = maxUDPPayload
			}
			// Downstream in TXT Answer so 8.8.8.8 and other public resolvers work (they don't strip TXT).
			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   responseTTL,
					Data:  nil,
				},
			}
			// Per-request limit using actual question name so 512-byte responses always fit.
			maxPayloadForReq, minimalWireSize := computeMaxPayloadForResponse(rec, maxSize)
			if minimalWireSize > maxSize {
				// Minimal response (empty payload) already exceeds maxSize; send valid TC=1 (no answer) if it fits.
				tcResp := &dns.Message{
					ID:         rec.Resp.ID,
					Flags:      rec.Resp.Flags | 0x02, // TC = 1
					Question:   rec.Resp.Question,
					Answer:     nil,
					Additional: rec.Resp.Additional,
				}
				tcBuf, err := tcResp.WireFormat()
				if err == nil && len(tcBuf) <= maxSize {
					_, _ = dnsConn.WriteTo(tcBuf, rec.Addr)
				}
				continue
			}

			if rec.PongResponse {
				// Health-check PING: respond with literal "PONG" or with N bytes (MTU discovery).
				// When the client requests N bytes (PongPayloadSize), send exactly N bytes of payload
				// (capped by maxPayloadForReq so the response fits), so the client can verify the path.
				if rec.PongPayloadSize > 0 {
					pongN := rec.PongPayloadSize
					if pongN > maxPayloadForReq {
						pongN = maxPayloadForReq
					}
					rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, pongN))
					if os.Getenv("DNSTT_DEBUG") != "" {
						log.Printf("DNSTT_DEBUG: PONG sent requested=%d actual_payload=%d", rec.PongPayloadSize, pongN)
					}
				} else {
					pongEnc := dns.EncodeRDataTXT([]byte("PONG"))
					if minimalWireSize+len(pongEnc) <= maxSize {
						rec.Resp.Answer[0].Data = pongEnc
					} else {
						// Wire contract: {0x00} means explicit empty marker.
						rec.Resp.Answer[0].Data = dns.EncodeRDataTXT([]byte{0})
					}
					if os.Getenv("DNSTT_DEBUG") != "" {
						log.Printf("DNSTT_DEBUG: PONG sent (health) payload=4 bytes")
					}
				}
			} else {
				// Serialize data collection per client so concurrent goroutines
				// don't compete for the same outgoing queue and overflow the
				// single-element stash (which silently drops KCP segments).
				// Use TryLock to avoid thundering-herd: if another goroutine is
				// already collecting for this client, send an empty ACK immediately.
				item := clientCache.Get(rec.ClientID)
				if item == nil {
					item, _ = clientCache.GetOrSet(rec.ClientID, &clientState{})
				}
				cs := item.Value()
				if !cs.mu.TryLock() {
					// Latency-first contention path: do a zero-wait probe for one
					// packet before falling back to explicit empty marker.
					var payload bytes.Buffer
					limit := maxPayloadForReq
					if limit > maxEncodedPayload {
						limit = maxEncodedPayload
					}
					if p, ok := dequeueOneDownstreamNonBlocking(ttConn, rec.ClientID); ok {
						packetSize := 2 + len(p)
						if packetSize <= limit {
							binary.Write(&payload, binary.BigEndian, uint16(len(p)))
							payload.Write(p)
						} else {
							stashDownstreamWithBackpressure(ttConn, rec.ClientID, p)
						}
					}
					payloadBytes := payload.Bytes()
					if len(payloadBytes) == 0 {
						// Wire contract: {0x00} means explicit empty marker.
						payloadBytes = []byte{0}
					}
					rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(payloadBytes)
				} else {
					var payload bytes.Buffer
					limit := maxPayloadForReq
					if limit > maxEncodedPayload {
						limit = maxEncodedPayload
					}
					timer := time.NewTimer(maxResponseDelay)
					for {
						var p []byte
						unstash := ttConn.Unstash(rec.ClientID)
						outgoing := ttConn.OutgoingQueue(rec.ClientID)
						// When channel has pending records, don't wait long so we drain and avoid "channel full" drops.
						waitDelay := maxResponseDelay
						if len(ch) > 0 {
							waitDelay = 0
						}
						if !timer.Stop() {
							select {
							case <-timer.C:
							default:
							}
						}
						timer.Reset(waitDelay)
						select {
						case p = <-unstash:
						default:
							select {
							case p = <-unstash:
							case p = <-outgoing:
							default:
								select {
								case p = <-unstash:
								case p = <-outgoing:
								case <-timer.C:
								case nextRec = <-ch:
								}
							}
						}
						timer.Reset(0)

						if len(p) == 0 {
							// Timer/channel wakeup may race with packet arrival.
							// One final zero-wait probe avoids wasting this
							// response opportunity when data is already queued.
							if p2, ok := dequeueOneDownstreamNonBlocking(ttConn, rec.ClientID); ok {
								p = p2
							}
						}
						if len(p) == 0 {
							break
						}

						packetSize := 2 + len(p)
						if limit < packetSize {
							stashDownstreamWithBackpressure(ttConn, rec.ClientID, p)
							break
						}
						limit -= packetSize
						if int(uint16(len(p))) != len(p) {
							panic(len(p))
						}
						binary.Write(&payload, binary.BigEndian, uint16(len(p)))
						payload.Write(p)
					}
					timer.Stop()
					cs.mu.Unlock()

					payloadBytes := payload.Bytes()
					if len(payloadBytes) == 0 {
						// Wire contract: {0x00} means explicit empty marker.
						payloadBytes = []byte{0}
					}
					rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(payloadBytes)
				}
			}
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		// Do not truncate: cutting the buffer produces invalid DNS (client gets unexpected EOF).
		// We cap payload size when building (PONG and tunnel) so the response should fit.
		maxSize := rec.MaxResponseSize
		if maxSize <= 0 {
			maxSize = maxUDPPayload
		}
		if len(buf) > maxSize {
			log.Printf("response of %d bytes exceeds max %d; dropping to avoid invalid truncation", len(buf), maxSize)
			continue
		}

		// Now we actually send the message as a UDP packet.
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("WriteTo temporary error: %v", err)
			} else {
				log.Printf("WriteTo error: %v", err)
			}
			continue
		}
	}
	return nil
}

// computeMaxPayloadForResponse returns the maximum payload bytes (for Answer TXT
// RDATA) that fit in maxSize for this specific response (actual question name),
// and the minimal wire size (response with empty payload). If minimal wire size
// already exceeds maxSize, maxPayload is 0. Temporarily mutates rec.Resp.Answer[0].Data.
func computeMaxPayloadForResponse(rec *record, maxSize int) (maxPayload int, minimalWireSize int) {
	if len(rec.Resp.Answer) == 0 {
		return 0, 0
	}
	resp := rec.Resp
	resp.Answer[0].Data = dns.EncodeRDataTXT([]byte{})
	buf, err := resp.WireFormat()
	resp.Answer[0].Data = nil
	if err != nil {
		return 0, 0
	}
	minimalWireSize = len(buf)
	if minimalWireSize > maxSize {
		return 0, minimalWireSize
	}
	low, high := 0, 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err = resp.WireFormat()
		resp.Answer[0].Data = nil
		if err != nil {
			return 0, minimalWireSize
		}
		if len(buf) <= maxSize {
			low = mid
		} else {
			high = mid
		}
	}
	return low, minimalWireSize
}

// computePongPayloadForTargetWireSize returns the PONG payload size N such that
// the response wire size equals targetWireSize (for MTU discovery so the client
// can verify the path delivered that size). If exact match is not possible, returns
// the N that yields the largest wire size <= targetWireSize. Temporarily mutates
// rec.Resp.Answer[0].Data.
func computePongPayloadForTargetWireSize(rec *record, targetWireSize int) (pongPayload int, exact bool) {
	maxPayload, minimalWireSize := computeMaxPayloadForResponse(rec, targetWireSize)
	if minimalWireSize > targetWireSize || maxPayload == 0 {
		return 0, false
	}
	// Binary search for N such that wire size == targetWireSize.
	low, high := 0, maxPayload+1
	var bestN int
	for low <= high {
		mid := (low + high) / 2
		rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := rec.Resp.WireFormat()
		rec.Resp.Answer[0].Data = nil
		if err != nil {
			return 0, false
		}
		n := len(buf)
		if n == targetWireSize {
			return mid, true
		}
		if n < targetWireSize {
			bestN = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return bestN, false
}

// computeMaxEncodedPayload computes the maximum amount of downstream TXT RR
// data that keep the overall response size less than maxUDPPayload, in the
// worst case when the response answers a query that has a maximum-length name
// in its Question section. Returns 0 in the case that no amount of data makes
// the overall response size small enough.
//
// This function needs to be kept in sync with sendLoop with regard to how it
// builds candidate responses.
func computeMaxEncodedPayload(limit int) int {
	// 64+64+64+62 octets (max name), for TXT payload size search.
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		// Compute the encoded length of maxLengthName and that its
		// length is actually at the maximum of 255 octets.
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1 // For the terminating null label.
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{Name: maxLengthName, Type: dns.RRTypeTXT, Class: dns.RRTypeTXT},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: queryLimit, TTL: 0, Data: []byte{}},
		},
	}
	resp, _, _ := responseFor(query, dns.Name([][]byte{}))
	if resp == nil {
		return 0
	}
	resp.Answer = []dns.RR{
		{Name: query.Question[0].Name, Type: dns.RRTypeTXT, Class: query.Question[0].Class, TTL: responseTTL, Data: nil},
	}

	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

// fecShardsFromEnv returns (dataShards, parityShards) from DNSTT_FEC_DATA and
// DNSTT_FEC_PARITY. Default (0, 0) disables FEC; e.g. use 2 and 1 on both client and server for lossy paths.
func fecShardsFromEnv() (dataShards, parityShards int) {
	dataShards = 0
	parityShards = 0
	if s := os.Getenv("DNSTT_FEC_DATA"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 10 {
			dataShards = n
		}
	}
	if s := os.Getenv("DNSTT_FEC_PARITY"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 10 {
			parityShards = n
		}
	}
	return dataShards, parityShards
}

func run(privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn, fallbackAddr *net.UDPAddr, socksTunnel bool) error {
	defer dnsConn.Close()

	log.Printf("pubkey %x", noise.PubkeyFromPrivkey(privkey))

	// We have a variable amount of room in which to encode downstream
	// packets in each response, because each response must contain the
	// query's Question section, which is of variable length. But we cannot
	// give dynamic packet size limits to KCP; the best we can do is set a
	// global maximum which no packet will exceed. We choose that maximum to
	// keep the UDP payload size under maxUDPPayload, even in the worst case
	// of a maximum-length name in the query's Question section.
	// Also cap by what fits in minSupportedResponseSize so clients on 512-byte
	// paths can receive full segments (sendLoop does not fragment; oversized
	// segments would be stashed and never fit in a 512-byte response).
	maxEncodedPayload := computeMaxEncodedPayload(maxUDPPayload)
	maxEncodedForMinResponse := computeMaxEncodedPayload(minSupportedResponseSize)
	// 2 bytes accounts for a packet length prefix.
	mtu := maxEncodedPayload - 2
	if maxEncodedForMinResponse-2 < mtu {
		mtu = maxEncodedForMinResponse - 2
	}
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", maxUDPPayload, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Start up the virtual PacketConn for turbotunnel.
	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
	dataShards, parityShards := fecShardsFromEnv()
	log.Printf("FEC dataShards=%d parityShards=%d", dataShards, parityShards)
	ln, err := kcp.ServeConn(nil, dataShards, parityShards, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()
	go func() {
		err := acceptSessions(ln, privkey, mtu, upstream, socksTunnel)
		if err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	// Send channel size: on slow/censored networks the sendLoop drains slowly, so a larger
	// buffer reduces "channel full" drops at the cost of memory.
	sendChanSize := 8192 * 20
	if s := os.Getenv("DNSTT_SEND_CHANNEL_SIZE"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 1 {
			const maxSendChanSize = 65536 * 20
			if n > maxSendChanSize {
				n = maxSendChanSize
			}
			sendChanSize = n
		}
	}
	ch := make(chan *record, sendChanSize)
	defer close(ch)

	if s := os.Getenv("DNSTT_RESPONSE_DELAY"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			maxResponseDelay = d
		}
	}
	log.Printf("maxResponseDelay %v", maxResponseDelay)

	// Create a fallback manager if an address is specified.
	var fallbackMgr *FallbackManager
	if fallbackAddr != nil {
		fallbackMgr = NewFallbackManager(dnsConn, fallbackAddr)
	}

	// Run multiple sendLoop goroutines so concurrent clients don't block
	// each other. Each goroutine independently collects downstream data and
	// sends responses; the shared channel distributes work automatically.
	numSendLoops := 64
	if s := os.Getenv("DNSTT_SEND_LOOPS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 1 {
			if n > 1024 {
				n = 1024
			}
			numSendLoops = n
		}
	}
	log.Printf("starting %d sendLoop goroutines", numSendLoops)
	clientCache := ttlcache.New(
		ttlcache.WithTTL[turbotunnel.ClientID, *clientState](idleTimeout * 2),
	)
	go clientCache.Start()
	for i := 0; i < numSendLoops; i++ {
		go func() {
			err := sendLoop(dnsConn, ttConn, ch, maxEncodedPayload, clientCache)
			if err != nil {
				log.Printf("sendLoop: %v", err)
			}
		}()
	}

	return recvLoop(domain, dnsConn, ttConn, ch, fallbackMgr)
}

func main() {
	var genKey bool
	var privkeyFilename string
	var privkeyString string
	var pubkeyFilename string
	var udpAddr string
	var fallbackAddrString string
	var tunnelMode string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -gen-key -privkey-file PRIVKEYFILE -pubkey-file PUBKEYFILE
  %[1]s -udp ADDR -privkey-file PRIVKEYFILE [-fallback FALLBACKADDR] [-tunnel tcp|socks] DOMAIN [UPSTREAMADDR]

Example:
  %[1]s -gen-key -privkey-file server.key -pubkey-file server.pub
  %[1]s -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000
  %[1]s -udp :53 -privkey-file server.key -tunnel socks t.example.com
  %[1]s -udp :53 -privkey-file server.key -fallback 127.0.0.1:8888 t.example.com 127.0.0.1:8000

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair; print to stdout or save to files")
	flag.IntVar(&maxUDPPayload, "mtu", maxUDPPayload, "maximum size of DNS responses")
	flag.StringVar(&privkeyString, "privkey", "", fmt.Sprintf("server private key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&privkeyFilename, "privkey-file", "", "read server private key from file (with -gen-key, write to file)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "with -gen-key, write server public key to file")
	flag.StringVar(&udpAddr, "udp", "", "UDP address to listen on (required)")
	flag.StringVar(&fallbackAddrString, "fallback", "", "UDP endpoint to forward non-DNS packets to (e.g., 127.0.0.1:8888)")
	flag.StringVar(&tunnelMode, "tunnel", "socks", "tcp: streams go to UPSTREAMADDR; socks: client chooses destination per stream")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if genKey {
		// -gen-key mode.
		if flag.NArg() != 0 || privkeyString != "" || udpAddr != "" || fallbackAddrString != "" {
			flag.Usage()
			os.Exit(1)
		}
		if err := generateKeypair(privkeyFilename, pubkeyFilename); err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate keypair: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Ordinary server mode.
		var socksTunnel bool
		switch tunnelMode {
		case "tcp":
			socksTunnel = false
		case "socks":
			socksTunnel = true
		default:
			fmt.Fprintf(os.Stderr, "-tunnel must be tcp or socks, not %q\n", tunnelMode)
			os.Exit(1)
		}
		if socksTunnel {
			if flag.NArg() != 1 {
				fmt.Fprintf(os.Stderr, "socks mode: %s -udp ... -tunnel socks DOMAIN (omit UPSTREAMADDR)\n", os.Args[0])
				os.Exit(1)
			}
		} else if flag.NArg() != 2 {
			flag.Usage()
			os.Exit(1)
		}
		domain, err := dns.ParseName(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
			os.Exit(1)
		}
		upstream := ""
		if !socksTunnel {
			upstream = flag.Arg(1)
			{
				upstreamHost, _, err := net.SplitHostPort(upstream)
				if err != nil {
					fmt.Fprintf(os.Stderr, "cannot parse upstream address %+q: %v\n", upstream, err)
					os.Exit(1)
				}
				upstreamIPAddr, err := net.ResolveIPAddr("ip", upstreamHost)
				if err != nil {
					log.Printf("warning: cannot resolve upstream host %+q: %v", upstreamHost, err)
				} else if upstreamIPAddr.IP == nil {
					fmt.Fprintf(os.Stderr, "cannot parse upstream address %+q: missing host in address\n", upstream)
					os.Exit(1)
				}
			}
		} else {
			log.Printf("tunnel mode socks: server will dial TCP/UDP targets requested by the client (secure egress)")
		}

		if udpAddr == "" {
			fmt.Fprintf(os.Stderr, "the -udp option is required\n")
			os.Exit(1)
		}
		dnsConn, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "opening UDP listener: %v\n", err)
			os.Exit(1)
		}

		var fallbackAddr *net.UDPAddr
		if fallbackAddrString != "" {
			fallbackAddr, err = net.ResolveUDPAddr("udp", fallbackAddrString)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot resolve fallback address %+q: %v\n", fallbackAddrString, err)
				os.Exit(1)
			}
		}

		if pubkeyFilename != "" {
			fmt.Fprintf(os.Stderr, "-pubkey-file may only be used with -gen-key\n")
			os.Exit(1)
		}

		var privkey []byte
		if privkeyFilename != "" && privkeyString != "" {
			fmt.Fprintf(os.Stderr, "only one of -privkey and -privkey-file may be used\n")
			os.Exit(1)
		} else if privkeyFilename != "" {
			var err error
			privkey, err = readKeyFromFile(privkeyFilename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot read privkey from file: %v\n", err)
				os.Exit(1)
			}
		} else if privkeyString != "" {
			var err error
			privkey, err = noise.DecodeKey(privkeyString)
			if err != nil {
				fmt.Fprintf(os.Stderr, "privkey format error: %v\n", err)
				os.Exit(1)
			}
		}
		if len(privkey) == 0 {
			log.Println("generating a temporary one-time keypair")
			log.Println("use the -privkey or -privkey-file option for a persistent server keypair")
			var err error
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		err = run(privkey, domain, upstream, dnsConn, fallbackAddr, socksTunnel)
		if err != nil {
			log.Fatal(err)
		}
	}
}
