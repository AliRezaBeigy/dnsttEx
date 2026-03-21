package kcp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

type wireSegment struct {
	cmd  uint8
	sn16 uint32
	raw  []byte
}

func splitWireSegments(t *testing.T, packet []byte) []wireSegment {
	t.Helper()
	segs := make([]wireSegment, 0, 4)
	for off := 0; off < len(packet); {
		if len(packet)-off < IKCP_OVERHEAD {
			t.Fatalf("truncated KCP packet: remain=%d (<%d)", len(packet)-off, IKCP_OVERHEAD)
		}
		cmd, _ := decodeCmdFrg(packet[off+2])
		sn := uint32(binary.LittleEndian.Uint16(packet[off+6:]))
		length := int(binary.LittleEndian.Uint16(packet[off+10:]))
		end := off + IKCP_OVERHEAD + length
		if end > len(packet) {
			t.Fatalf("invalid KCP packet length: off=%d len=%d total=%d", off, length, len(packet))
		}
		raw := append([]byte(nil), packet[off:end]...)
		segs = append(segs, wireSegment{cmd: cmd, sn16: sn, raw: raw})
		off = end
	}
	return segs
}

func TestHandleDownstreamNREQHeadMissingQueuesNMISOnly(t *testing.T) {
	t.Setenv("DNSTT_KCP_REPLAY_MISS_NOTIFY", "1")

	s := &UDPSession{
		kcp:              NewKCP(0x2233, func([]byte, int) {}),
		headerSize:       0,
		chPostProcessing: make(chan sendRequest, 16),
		die:              make(chan struct{}),
		downstreamReplay: newDownstreamReplay(),
	}

	// Store only a later segment. NREQ asks from sn=10, so head is missing.
	s.downstreamReplay.Add(11, 0, []byte{0x11, 0x22})
	s.handleDownstreamNREQ(10, 4)

	nmis := 0
	push := 0
	for {
		select {
		case req := <-s.chPostProcessing:
			wire := req.buffer[s.headerSize:]
			for _, seg := range splitWireSegments(t, wire) {
				switch seg.cmd {
				case IKCP_CMD_NMIS:
					nmis++
					if seg.sn16 != 10 {
						t.Fatalf("NMIS sn wire=%d want 10", seg.sn16)
					}
				case IKCP_CMD_PUSH:
					push++
				}
			}
			defaultBufferPool.Put(req.buffer)
		default:
			if nmis == 0 {
				t.Fatal("expected NMIS to be queued when replay head is missing")
			}
			if push != 0 {
				t.Fatalf("expected no PUSH replay when head missing, got %d", push)
			}
			return
		}
	}
}

func TestHandleDownstreamNREQHeadPresentQueuesReplayPush(t *testing.T) {
	s := &UDPSession{
		kcp:              NewKCP(0x2234, func([]byte, int) {}),
		headerSize:       0,
		chPostProcessing: make(chan sendRequest, 16),
		die:              make(chan struct{}),
		downstreamReplay: newDownstreamReplay(),
	}

	s.downstreamReplay.Add(10, 0, []byte{0xAA})
	s.downstreamReplay.Add(11, 0, []byte{0xBB})
	s.handleDownstreamNREQ(10, 2)

	nmis := 0
	push := 0
	for {
		select {
		case req := <-s.chPostProcessing:
			wire := req.buffer[s.headerSize:]
			for _, seg := range splitWireSegments(t, wire) {
				switch seg.cmd {
				case IKCP_CMD_NMIS:
					nmis++
				case IKCP_CMD_PUSH:
					push++
				}
			}
			defaultBufferPool.Put(req.buffer)
		default:
			if push == 0 {
				t.Fatal("expected replay PUSH when NREQ head exists in replay cache")
			}
			if nmis != 0 {
				t.Fatalf("unexpected NMIS while replay head exists: %d", nmis)
			}
			return
		}
	}
}

func TestHandleDownstreamNREQHeadMissingNotifyDisabledQueuesNothing(t *testing.T) {
	t.Setenv("DNSTT_KCP_REPLAY_MISS_NOTIFY", "0")

	s := &UDPSession{
		kcp:              NewKCP(0x2235, func([]byte, int) {}),
		headerSize:       0,
		chPostProcessing: make(chan sendRequest, 16),
		die:              make(chan struct{}),
		downstreamReplay: newDownstreamReplay(),
	}

	// Replay has only later data, but NREQ asks for a missing head.
	s.downstreamReplay.Add(11, 0, []byte{0xEE})
	s.handleDownstreamNREQ(10, 2)

	select {
	case req := <-s.chPostProcessing:
		defaultBufferPool.Put(req.buffer)
		t.Fatal("expected no queued frames when replay miss notify is disabled and head is missing")
	default:
		// expected
	}
}

func TestHandleDownstreamNREQZeroLengthPayloadStillReplays(t *testing.T) {
	s := &UDPSession{
		kcp:              NewKCP(0x2236, func([]byte, int) {}),
		headerSize:       0,
		chPostProcessing: make(chan sendRequest, 16),
		die:              make(chan struct{}),
		downstreamReplay: newDownstreamReplay(),
	}

	// Zero-length payload is a valid stored PUSH and must not be treated as missing.
	s.downstreamReplay.Add(10, 0, nil)
	s.handleDownstreamNREQ(10, 1)

	gotPush := false
	for {
		select {
		case req := <-s.chPostProcessing:
			wire := req.buffer[s.headerSize:]
			for _, seg := range splitWireSegments(t, wire) {
				if seg.cmd == IKCP_CMD_PUSH {
					gotPush = true
					if len(seg.raw) != IKCP_OVERHEAD {
						t.Fatalf("zero-length replayed PUSH should be header-only, got %d bytes", len(seg.raw))
					}
				}
			}
			defaultBufferPool.Put(req.buffer)
		default:
			if !gotPush {
				t.Fatal("expected replayed PUSH for zero-length payload")
			}
			return
		}
	}
}

func TestHandleDownstreamNREQResolveWireLapToFullSN(t *testing.T) {
	s := &UDPSession{
		kcp:              NewKCP(0x2237, func([]byte, int) {}),
		headerSize:       0,
		chPostProcessing: make(chan sendRequest, 16),
		die:              make(chan struct{}),
		downstreamReplay: newDownstreamReplay(),
	}

	// Simulate long-lived sender where requested wire SN=0 refers to full SN=65536.
	s.kcp.snd_nxt = 70000
	expectedPayload := []byte{0x65, 0x53, 0x36}
	s.downstreamReplay.Add(65536, 0, expectedPayload)
	s.handleDownstreamNREQ(0, 1)

	gotPush := false
	for {
		select {
		case req := <-s.chPostProcessing:
			wire := req.buffer[s.headerSize:]
			for _, seg := range splitWireSegments(t, wire) {
				if seg.cmd != IKCP_CMD_PUSH {
					continue
				}
				gotPush = true
				if len(seg.raw) != IKCP_OVERHEAD+len(expectedPayload) {
					t.Fatalf("unexpected replayed PUSH length=%d", len(seg.raw))
				}
				body := seg.raw[IKCP_OVERHEAD:]
				if !bytes.Equal(body, expectedPayload) {
					t.Fatalf("replayed payload mismatch got=%v want=%v", body, expectedPayload)
				}
			}
			defaultBufferPool.Put(req.buffer)
		default:
			if !gotPush {
				t.Fatal("expected replayed PUSH for wire SN lap resolution case")
			}
			return
		}
	}
}

func TestKCPIntegrationNREQReplayAndReplayMiss(t *testing.T) {
	cases := []struct {
		name            string
		dropOnWire      string // "head" or "tail"
		dropHeadReplay  bool
		expectRecovered bool
		expectReplaySN uint32
	}{
		{
			name:            "replay_head_present_recovers_stream",
			dropOnWire:      "head",
			dropHeadReplay:  false,
			expectRecovered: true,
		},
		{
			name:            "replay_tail_loss_recovers_with_idle_probe",
			dropOnWire:      "tail",
			dropHeadReplay:  false,
			expectRecovered: true,
		},
		{
			name:            "replay_head_missing_sends_nmis",
			dropOnWire:      "head",
			dropHeadReplay:  true,
			expectRecovered: false,
			expectReplaySN:  0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			serverReplay := newDownstreamReplay()
			var (
				droppedWire    bool
				firstPushSN    uint32
				haveFirstPush  bool
				nreqSeen       int
				nmisSent       int
			)

			const conv = 0x4455
			var server, client *KCP

			client = NewKCP(conv, func(buf []byte, size int) {
				for _, seg := range splitWireSegments(t, append([]byte(nil), buf[:size]...)) {
					if seg.cmd == IKCP_CMD_NREQ {
						nreqSeen++
					}
					if ret := server.Input(seg.raw, IKCP_PACKET_REGULAR, true); ret != 0 {
						t.Fatalf("server input from client output failed: ret=%d", ret)
					}
				}
			})
			client.SetClientResendRequests(true)
			client.NoDelay(1, 10, 2, 1)

			server = NewKCP(conv, func(buf []byte, size int) {
				for _, seg := range splitWireSegments(t, append([]byte(nil), buf[:size]...)) {
					if seg.cmd == IKCP_CMD_PUSH && haveFirstPush && !droppedWire {
						headSN := firstPushSN
						tailSN := (firstPushSN + 1) & (kcpSNMod - 1)
						shouldDrop := false
						switch tc.dropOnWire {
						case "head":
							shouldDrop = seg.sn16 == headSN
						case "tail":
							shouldDrop = seg.sn16 == tailSN
						}
						if shouldDrop {
							droppedWire = true
							continue
						}
					}
					if ret := client.Input(seg.raw, IKCP_PACKET_REGULAR, true); ret != 0 {
						t.Fatalf("client input from server output failed: ret=%d", ret)
					}
				}
			})
			server.SetAssumeDeliveredAfterSend(true)
			server.NoDelay(1, 10, 2, 1)

			server.SetOutboundPushHook(func(sn uint32, frg uint8, payload []byte) {
				if !haveFirstPush {
					haveFirstPush = true
					firstPushSN = sn & (kcpSNMod - 1)
				}
				if tc.dropHeadReplay && haveFirstPush && (sn&(kcpSNMod-1)) == firstPushSN {
					return
				}
				serverReplay.Add(sn, frg, payload)
			})

			server.SetResendRequestHandler(func(wireFirstMissingSN uint32, maxSegments uint32) {
				firstFull, ok := serverReplay.resolveWireSN(wireFirstMissingSN, server.snd_nxt)
				if !ok {
					firstFull = expandSN16(server.snd_nxt, wireFirstMissingSN)
				}
				if _, _, found := serverReplay.payloadForNREQ(firstFull); !found {
					var seg segment
					seg.conv = server.conv
					seg.cmd = IKCP_CMD_NMIS
					seg.sn = wireFirstMissingSN & (kcpSNMod - 1)
					seg.wnd = uint16(min(int(server.wnd_unused()), 255))
					seg.ts = currentMs()
					out := make([]byte, IKCP_OVERHEAD)
					seg.encode(out)
					nmisSent++
					if ret := client.Input(out, IKCP_PACKET_REGULAR, true); ret != 0 {
						t.Fatalf("client input NMIS failed: ret=%d", ret)
					}
					return
				}
				for i := uint32(0); i < maxSegments; i++ {
					sn := firstFull + i
					payload, frg, found := serverReplay.payloadForNREQ(sn)
					if !found {
						continue
					}
					var seg segment
					seg.conv = server.conv
					seg.cmd = IKCP_CMD_PUSH
					seg.sn = sn
					seg.frg = frg
					seg.wnd = uint16(min(int(server.wnd_unused()), 255))
					seg.ts = currentMs()
					seg.una = server.rcv_nxt
					seg.data = payload
					out := make([]byte, IKCP_OVERHEAD+len(payload))
					tail := seg.encode(out)
					copy(tail, payload)
					if ret := client.Input(out, IKCP_PACKET_REGULAR, true); ret != 0 {
						t.Fatalf("client input replayed PUSH failed: ret=%d", ret)
					}
				}
			})

			// Two PUSH segments are enough to create a real receive-gap when the head is dropped.
			payload := bytes.Repeat([]byte{0xAB}, int(server.mss)+1)
			if ret := server.Send(payload); ret != 0 {
				t.Fatalf("server send failed: ret=%d", ret)
			}
			server.flush(IKCP_FLUSH_FULL)
			if !droppedWire {
				t.Fatalf("test setup failed: no downstream PUSH dropped for mode %q", tc.dropOnWire)
			}

			deadline := time.Now().Add(4 * time.Second)
			recovered := false
			for time.Now().Before(deadline) {
				if n := client.PeekSize(); n == len(payload) {
					got := make([]byte, len(payload))
					if rn := client.Recv(got); rn != len(payload) {
						t.Fatalf("client recv len=%d want=%d", rn, len(payload))
					}
					if !bytes.Equal(got, payload) {
						t.Fatal("client payload mismatch after replay")
					}
					recovered = true
					break
				}
				server.Update()
				client.maybeRetryNreqOnStall()
				client.Update()
				time.Sleep(5 * time.Millisecond)
			}

			if nreqSeen == 0 {
				t.Fatal("expected at least one NREQ after dropped head segment")
			}
			if tc.expectRecovered {
				if !recovered {
					t.Fatal("expected replay recovery when replay head exists")
				}
				if nmisSent != 0 {
					t.Fatalf("did not expect NMIS in recovery case, got %d", nmisSent)
				}
			} else {
				if recovered {
					t.Fatal("unexpected recovery when replay head was intentionally absent")
				}
				if nmisSent == 0 {
					t.Fatal("expected NMIS when replay head is missing")
				}
				if client.lastReplayMissFullSn != tc.expectReplaySN {
					t.Fatalf("client replay miss full sn=%d want=%d", client.lastReplayMissFullSn, tc.expectReplaySN)
				}
			}
		})
	}
}

