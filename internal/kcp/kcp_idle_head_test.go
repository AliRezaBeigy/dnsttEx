package kcp

import (
	"testing"
	"time"
)

func TestIdleHeadProbeColdStartNoRcvProgress(t *testing.T) {
	t.Setenv("DNSTT_KCP_NREQ_IDLE_HEAD", "40ms")
	k := NewKCP(0xabc, func([]byte, int) {})
	k.SetClientResendRequests(true)
	// No in-order data yet: rcv_nxt=0, lastRcvNxtAdvanceMs=0, PeekSize()<0
	k.maybeRetryNreqOnStall()
	if len(k.nreqList) != 0 {
		t.Fatalf("want no immediate idle NREQ, got nreqList=%v", k.nreqList)
	}
	time.Sleep(55 * time.Millisecond)
	k.maybeRetryNreqOnStall()
	if len(k.nreqList) != 1 {
		t.Fatalf("want 1 idle NREQ after cold-start wait, got nreqList=%v", k.nreqList)
	}
	if k.nreqList[0].first != 0 {
		t.Fatalf("nreq first=%d want 0", k.nreqList[0].first)
	}
}
