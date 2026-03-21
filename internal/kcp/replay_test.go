package kcp

import "testing"

func TestResolveWireSN(t *testing.T) {
	r := newDownstreamReplay()
	r.Add(0, 0, []byte{1})
	r.Add(1, 0, []byte{2})
	r.Add(2, 0, []byte{3})

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
