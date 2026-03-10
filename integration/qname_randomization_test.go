//go:build integration

package integration_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

)

// qnameRandomizingUDPRelay simulates Google DNS 0x20 behavior:
// it randomizes the case of labels in the query QNAME, forwards to
// the server, then verifies the response echoes the randomized case
// in the question section. If the case doesn't match, it sends ServFail
// to the client (exactly as Google DNS would).
type qnameRandomizingUDPRelay struct {
	ln         *net.UDPConn
	serverAddr *net.UDPAddr
	done       chan struct{}
	rng        *rand.Rand

	mu         sync.Mutex
	clientAddr *net.UDPAddr

	mismatches atomic.Int64
	forwarded  atomic.Int64
}

func newQNAMERandomizingUDPRelay(t testing.TB, serverAddrStr string) *qnameRandomizingUDPRelay {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		t.Fatalf("resolve server addr: %v", err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	r := &qnameRandomizingUDPRelay{
		ln:         ln,
		serverAddr: serverAddr,
		done:       make(chan struct{}),
		rng:        rand.New(rand.NewSource(42)),
	}
	go r.loop()
	return r
}

func (r *qnameRandomizingUDPRelay) Addr() string {
	return r.ln.LocalAddr().String()
}

func (r *qnameRandomizingUDPRelay) Close() {
	close(r.done)
	r.ln.Close()
}

// randomizeQNAMEWire applies 0x20 case randomization directly to the wire
// bytes of a DNS query. It flips the 0x20 bit for ASCII letters in the
// question name labels. Returns the modified packet and the randomized name
// bytes (offset 12 through end of QNAME) for later verification.
func (r *qnameRandomizingUDPRelay) randomizeQNAMEWire(pkt []byte) (modified []byte, qnameBytes []byte) {
	modified = make([]byte, len(pkt))
	copy(modified, pkt)

	if len(modified) < 13 {
		return modified, nil
	}

	// Question name starts at offset 12 (right after the 12-byte header).
	offset := 12
	qnameStart := offset
	for offset < len(modified) {
		length := int(modified[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xc0 != 0 {
			offset += 2
			break
		}
		offset++
		for i := 0; i < length && offset+i < len(modified); i++ {
			b := modified[offset+i]
			if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
				if r.rng.Intn(2) == 0 {
					modified[offset+i] = b ^ 0x20 // flip case
				}
			}
		}
		offset += length
	}

	qnameBytes = make([]byte, offset-qnameStart)
	copy(qnameBytes, modified[qnameStart:offset])
	return modified, qnameBytes
}

// extractQNAMEWire extracts the raw QNAME bytes from a DNS wire packet.
func extractQNAMEWire(pkt []byte) []byte {
	if len(pkt) < 13 {
		return nil
	}
	offset := 12
	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xc0 != 0 {
			offset += 2
			break
		}
		offset += 1 + length
	}
	return pkt[12:offset]
}

// buildServFail constructs a minimal ServFail DNS response for the given query ID.
func buildServFail(queryID uint16) []byte {
	var buf [12]byte
	binary.BigEndian.PutUint16(buf[0:2], queryID)
	binary.BigEndian.PutUint16(buf[2:4], 0x8002) // QR=1, RCODE=SERVFAIL
	return buf[:]
}

func (r *qnameRandomizingUDPRelay) loop() {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return
	}
	defer serverConn.Close()

	type pending struct {
		clientAddr    *net.UDPAddr
		randomQNAME   []byte
		originalQuery []byte
	}
	var pendingMu sync.Mutex
	pendingMap := make(map[uint16]*pending) // keyed by DNS ID sent to server

	// Server → client (verify 0x20 case match, then forward or ServFail).
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			if n < 12 {
				continue
			}
			respID := binary.BigEndian.Uint16(buf[0:2])

			pendingMu.Lock()
			p := pendingMap[respID]
			delete(pendingMap, respID)
			pendingMu.Unlock()

			if p == nil {
				continue
			}

			respQNAME := extractQNAMEWire(buf[:n])
			if !bytes.Equal(p.randomQNAME, respQNAME) {
				r.mismatches.Add(1)
				sf := buildServFail(respID)
				r.ln.WriteToUDP(sf, p.clientAddr)
				continue
			}

			r.forwarded.Add(1)
			r.ln.WriteToUDP(buf[:n], p.clientAddr)
		}
	}()

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := r.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}

		modified, randomQNAME := r.randomizeQNAMEWire(buf[:n])
		modifiedID := binary.BigEndian.Uint16(modified[0:2])

		pendingMu.Lock()
		pendingMap[modifiedID] = &pending{
			clientAddr:    clientAddr,
			randomQNAME:   randomQNAME,
			originalQuery: append([]byte(nil), buf[:n]...),
		}
		pendingMu.Unlock()

		serverConn.WriteToUDP(modified, r.serverAddr)
	}
}

// TestTunnelSurvivesQNAMERandomization verifies the full dnstt tunnel works
// when an intermediate resolver applies DNS 0x20 case randomization to queries
// and rejects responses that don't echo the randomized case (Google DNS behavior).
func TestTunnelSurvivesQNAMERandomization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 0x20 test in short mode")
	}

	var stderrBuf bytes.Buffer
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newQNAMERandomizingUDPRelay(t, addr)
		},
		&stderrBuf, nil)

	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	payload := []byte("hello through 0x20 randomization relay")
	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, len(payload)+256)
	n, err := io.ReadAtLeast(conn, got, len(payload))
	if err != nil {
		t.Fatalf("read (got %d bytes): %v\nclient stderr:\n%s", n, err, stderrBuf.String())
	}
	if !bytes.Equal(got[:n], payload) {
		t.Errorf("echo mismatch: sent %q, got %q", payload, got[:n])
	}

	t.Logf("tunnel data echoed successfully through 0x20-randomizing relay")
}
