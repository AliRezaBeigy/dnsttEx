package kcp

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestInputNMISAccepted(t *testing.T) {
	k := NewKCP(0xabcd1234, func([]byte, int) {})
	k.rcv_nxt = 42

	var seg segment
	seg.conv = k.conv
	seg.cmd = IKCP_CMD_NMIS
	seg.sn = 42 & (kcpSNMod - 1)
	seg.wnd = 32
	seg.ts = 0
	seg.una = 0
	seg.data = nil
	buf := make([]byte, IKCP_OVERHEAD)
	seg.encode(buf)

	if ret := k.Input(buf, IKCP_PACKET_REGULAR, false); ret != 0 {
		t.Fatalf("Input NMIS: got %d want 0", ret)
	}
}

func TestNMISInvokesReplayMissHandler(t *testing.T) {
	var calls atomic.Int32
	k := NewKCP(0xabcd1234, func([]byte, int) {})
	k.SetClientResendRequests(true)
	k.SetReplayMissHandler(func(miss uint32) {
		if miss != 42 {
			t.Errorf("handler miss=%d want 42", miss)
		}
		calls.Add(1)
	})
	k.rcv_nxt = 42

	var seg segment
	seg.conv = k.conv
	seg.cmd = IKCP_CMD_NMIS
	seg.sn = 42 & (kcpSNMod - 1)
	seg.wnd = 32
	seg.ts = 0
	seg.una = 0
	buf := make([]byte, IKCP_OVERHEAD)
	seg.encode(buf)

	if ret := k.Input(buf, IKCP_PACKET_REGULAR, false); ret != 0 {
		t.Fatalf("Input NMIS: got %d want 0", ret)
	}
	if calls.Load() != 1 {
		t.Fatalf("replay miss handler calls=%d want 1", calls.Load())
	}
}

func TestNMISCooldownSuppressesNREQ(t *testing.T) {
	// Minimum enforced cooldown is 500ms (see nmisNreqCooldownMs).
	t.Setenv("DNSTT_KCP_NMIS_NREQ_COOLDOWN", "500ms")
	k := NewKCP(1, func([]byte, int) {})
	k.SetClientResendRequests(true)
	k.rcv_nxt = 10

	var seg segment
	seg.conv = k.conv
	seg.cmd = IKCP_CMD_NMIS
	seg.sn = 10 & (kcpSNMod - 1)
	seg.wnd = 32
	seg.ts = 0
	seg.una = 0
	buf := make([]byte, IKCP_OVERHEAD)
	seg.encode(buf)
	if ret := k.Input(buf, IKCP_PACKET_REGULAR, false); ret != 0 {
		t.Fatalf("Input NMIS: %d", ret)
	}

	k.scheduleResendRequest(10, 8, true)
	if len(k.nreqList) != 0 {
		t.Fatalf("expected NREQ suppressed right after NMIS, got nreqList=%v", k.nreqList)
	}

	time.Sleep(600 * time.Millisecond)
	k.scheduleResendRequest(10, 8, true)
	if len(k.nreqList) != 1 {
		t.Fatalf("after cooldown want 1 nreq item, got %d", len(k.nreqList))
	}
}
