package kcp

import (
	"testing"
	"time"
)

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

func TestReplayEvictsStaleByWallClock(t *testing.T) {
	me, mb, _ := replayLimits()
	now := time.Unix(1_700_000_000, 0)
	r := &downstreamReplay{
		maxEntries: me,
		maxBytes:   mb,
		maxAge:     30 * time.Second,
		bySN: map[uint32]replaySeg{
			1: {payload: []byte{1}, frg: 0, addedAt: now.Add(-31 * time.Second)},
			2: {payload: []byte{2}, frg: 0, addedAt: now.Add(-10 * time.Second)},
		},
		order:    []uint32{1, 2},
		curBytes: 2,
	}
	r.mu.Lock()
	r.evictStaleLocked(now)
	r.mu.Unlock()
	if _, ok := r.bySN[1]; ok {
		t.Fatal("segment older than maxAge should be evicted")
	}
	if _, ok := r.bySN[2]; !ok {
		t.Fatal("recent segment should remain")
	}
	if len(r.order) != 1 || r.order[0] != 2 {
		t.Fatalf("order = %v, want [2]", r.order)
	}
	if r.curBytes != 1 {
		t.Fatalf("curBytes = %d, want 1", r.curBytes)
	}
}
