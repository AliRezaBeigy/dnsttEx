package dns

import "testing"

func TestDownstreamDataFrameRoundTrip(t *testing.T) {
	in := []byte{0x12, 0x34, 0x56}
	wire := EncodeDownstreamDataFrame(in)
	flag, data, hint, err := ParseDownstreamFrame(wire)
	if err != nil {
		t.Fatalf("ParseDownstreamFrame(data): %v", err)
	}
	if flag != DownstreamFlagData {
		t.Fatalf("flag=%#x want=%#x", flag, DownstreamFlagData)
	}
	if hint != (DownstreamHint{}) {
		t.Fatalf("unexpected hint for data frame: %+v", hint)
	}
	if len(data) != len(in) {
		t.Fatalf("data length=%d want=%d", len(data), len(in))
	}
	for i := range in {
		if data[i] != in[i] {
			t.Fatalf("data[%d]=%#x want=%#x", i, data[i], in[i])
		}
	}
}

func TestDownstreamHintFrameRoundTrip(t *testing.T) {
	in := DownstreamHint{
		FirstMissingSN: 1234,
		HighestSentSN:  1400,
		SuggestedCount: 32,
		HintTTLms:      300,
	}
	wire := EncodeDownstreamHintFrame(in)
	flag, data, out, err := ParseDownstreamFrame(wire)
	if err != nil {
		t.Fatalf("ParseDownstreamFrame(hint): %v", err)
	}
	if flag != DownstreamFlagHint {
		t.Fatalf("flag=%#x want=%#x", flag, DownstreamFlagHint)
	}
	if len(data) != 0 {
		t.Fatalf("hint data length=%d want=0", len(data))
	}
	if out != in {
		t.Fatalf("hint mismatch got=%+v want=%+v", out, in)
	}
}

func TestDownstreamHintFrameRejectsInvalidLength(t *testing.T) {
	short := []byte{DownstreamFlagHint, 1, 2, 3}
	if _, _, _, err := ParseDownstreamFrame(short); err == nil {
		t.Fatal("expected invalid hint length error")
	}
}

func TestDownstreamHintFrameRejectsZeroTTL(t *testing.T) {
	wire := EncodeDownstreamHintFrame(DownstreamHint{
		FirstMissingSN: 1,
		HighestSentSN:  2,
		SuggestedCount: 1,
		HintTTLms:      0,
	})
	if _, _, _, err := ParseDownstreamFrame(wire); err == nil {
		t.Fatal("expected zero ttl error")
	}
}

