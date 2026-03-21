package kcp

import (
	"bytes"
	"testing"
)

func encodeTestPush(conv, sn uint32, payload []byte) []byte {
	seg := segment{
		conv: conv,
		cmd:  IKCP_CMD_PUSH,
		frg:  0,
		wnd:  200,
		ts:   0,
		sn:   sn,
		una:  0,
		data: payload,
	}
	out := make([]byte, IKCP_OVERHEAD+len(payload))
	_ = seg.encodeWireHeader(out)
	copy(out[IKCP_OVERHEAD:], payload)
	return out
}

func TestCaptureOutboundKCPPushes(t *testing.T) {
	r := newDownstreamReplay()
	buf := append(append(
		encodeTestPush(0xabc, 0, []byte{9, 9, 9}),
		encodeTestPush(0xabc, 1, []byte{7})...),
		encodeTestPush(0xabc, 2, nil)...)
	captureOutboundKCPPushes(r, buf)
	for _, sn := range []uint32{0, 1, 2} {
		p, ok := r.payloadForNREQ(sn)
		if !ok {
			t.Fatalf("missing sn=%d after capture", sn)
		}
		if sn == 2 && len(p) != 0 {
			t.Fatalf("sn=2 payload: len=%d want 0", len(p))
		}
	}
	p0, _ := r.payloadForNREQ(0)
	if !bytes.Equal(p0, []byte{9, 9, 9}) {
		t.Fatalf("sn=0 payload %v", p0)
	}
}

func TestResolveWireSN(t *testing.T) {
	r := newDownstreamReplay()
	r.Add(0, []byte{1})
	r.Add(1, []byte{2})
	r.Add(2, []byte{3})

	sn, ok := r.resolveWireSN(0, 10)
	if !ok || sn != 0 {
		t.Fatalf("resolveWireSN(0, 10) = (%d, %v), want (0, true)", sn, ok)
	}
	sn, ok = r.resolveWireSN(0, 70000)
	if !ok || sn != 0 {
		t.Fatalf("resolveWireSN(0, 70000) = (%d, %v), want (0, true) — must not pick lap 65536 when sn=0 is in map", sn, ok)
	}
	sn, ok = r.resolveWireSN(2, 10)
	if !ok || sn != 2 {
		t.Fatalf("resolveWireSN(2, 10) = (%d, %v), want (2, true)", sn, ok)
	}
}
