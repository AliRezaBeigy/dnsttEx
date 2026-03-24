package kcp

import "testing"

func TestBeyondWindowDropSchedulesNreqOncePerRcvNxt(t *testing.T) {
	k := NewKCP(1, func([]byte, int) {})
	k.SetClientResendRequests(true)
	k.rcv_wnd = 8
	k.rcv_nxt = 10
	// sn >= rcv_nxt + rcv_wnd  =>  18 >= 18
	_ = k.parse_data(segment{sn: 18, data: []byte("a")})
	if len(k.nreqList) != 1 {
		t.Fatalf("want 1 nreq, got %v", k.nreqList)
	}
	if k.nreqList[0].first != 10 || k.nreqList[0].count != 8 {
		t.Fatalf("nreq item=%+v want first=10 count=8", k.nreqList[0])
	}
	if k.beyondWndNreqForRcvNxt != 10 {
		t.Fatalf("beyondWndNreqForRcvNxt=%d want 10", k.beyondWndNreqForRcvNxt)
	}
	_ = k.parse_data(segment{sn: 19, data: []byte("b")})
	if len(k.nreqList) != 1 {
		t.Fatalf("second beyond-window must not schedule again for same rcv_nxt, got len=%d", len(k.nreqList))
	}

	_ = k.parse_data(segment{sn: 10, data: []byte("h")})
	if k.rcv_nxt != 11 {
		t.Fatalf("rcv_nxt=%d want 11", k.rcv_nxt)
	}
	if k.beyondWndNreqForRcvNxt != 0xFFFFFFFF {
		t.Fatalf("beyondWndNreqForRcvNxt should reset after progress, got %d", k.beyondWndNreqForRcvNxt)
	}
}

func TestBeyondWindowNoNreqWhenClientNreqDisabled(t *testing.T) {
	k := NewKCP(1, func([]byte, int) {})
	k.rcv_wnd = 4
	k.rcv_nxt = 0
	_ = k.parse_data(segment{sn: 10, data: []byte("x")})
	if len(k.nreqList) != 0 {
		t.Fatalf("want no nreq when clientSendNreq false, got %v", k.nreqList)
	}
}
