package kcp

import "testing"

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
