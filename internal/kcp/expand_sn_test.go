package kcp

import "testing"

func TestExpandSN16(t *testing.T) {
	tests := []struct {
		anchor, wire, want uint32
	}{
		{0, 0, 0},
		{0, 3, 3},
		{3, 0, 0},
		{65535, 0, 65536},
		{65536, 0, 65536},
		{65536, 1, 65537},
		{65537, 65535, 65535},
		{100000, 0x8000, 98304}, // 100000 -> low 0x8690, wire 0x8000 -> delta
	}
	for _, tc := range tests {
		got := expandSN16(tc.anchor, tc.wire)
		if got != tc.want {
			t.Fatalf("expandSN16(anchor=%d, wire=%d) = %d, want %d", tc.anchor, tc.wire, got, tc.want)
		}
	}
}
