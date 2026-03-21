package kcp

import "testing"

func TestEncodeDecodeCmdFrgLegacyAndExtensions(t *testing.T) {
	legacy := []struct {
		cmd uint8
		frg uint8
	}{
		{IKCP_CMD_PUSH, 7},
		{IKCP_CMD_ACK, 0},
		{IKCP_CMD_WASK, 0},
		{IKCP_CMD_WINS, 0},
	}
	for _, tc := range legacy {
		wire := encodeCmdFrg(tc.cmd, tc.frg)
		gotCmd, gotFrg := decodeCmdFrg(wire)
		if gotCmd != tc.cmd || gotFrg != tc.frg {
			t.Fatalf("legacy roundtrip cmd=%d frg=%d -> got cmd=%d frg=%d", tc.cmd, tc.frg, gotCmd, gotFrg)
		}
	}

	ext := []uint8{IKCP_CMD_NREQ, IKCP_CMD_NMIS}
	for _, cmd := range ext {
		wire := encodeCmdFrg(cmd, 0)
		gotCmd, gotFrg := decodeCmdFrg(wire)
		if gotCmd != cmd || gotFrg != 0 {
			t.Fatalf("extension roundtrip cmd=%d -> got cmd=%d frg=%d", cmd, gotCmd, gotFrg)
		}
	}
}

