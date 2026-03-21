package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	DownstreamFlagData byte = 0x00
	DownstreamFlagHint byte = 0x01

	downstreamHintPayloadLen = 13
)

var (
	ErrDownstreamFrameEmpty          = errors.New("downstream frame is empty")
	ErrUnknownDownstreamFlag         = errors.New("unknown downstream frame flag")
	ErrInvalidDownstreamHintLength   = errors.New("invalid downstream hint frame length")
	ErrInvalidDownstreamHintRange    = errors.New("invalid downstream hint range")
	ErrInvalidDownstreamHintTTL      = errors.New("invalid downstream hint ttl")
)

type DownstreamHint struct {
	FirstMissingSN uint32
	HighestSentSN  uint32
	SuggestedCount uint16
	HintTTLms      uint16
}

func EncodeDownstreamDataFrame(payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = DownstreamFlagData
	copy(out[1:], payload)
	return out
}

func EncodeDownstreamHintFrame(h DownstreamHint) []byte {
	out := make([]byte, downstreamHintPayloadLen)
	out[0] = DownstreamFlagHint
	binary.BigEndian.PutUint32(out[1:5], h.FirstMissingSN)
	binary.BigEndian.PutUint32(out[5:9], h.HighestSentSN)
	binary.BigEndian.PutUint16(out[9:11], h.SuggestedCount)
	binary.BigEndian.PutUint16(out[11:13], h.HintTTLms)
	return out
}

func ParseDownstreamFrame(payload []byte) (flag byte, data []byte, hint DownstreamHint, err error) {
	if len(payload) == 0 {
		return 0, nil, DownstreamHint{}, ErrDownstreamFrameEmpty
	}
	flag = payload[0]
	switch flag {
	case DownstreamFlagData:
		return flag, payload[1:], DownstreamHint{}, nil
	case DownstreamFlagHint:
		if len(payload) != downstreamHintPayloadLen {
			return 0, nil, DownstreamHint{}, fmt.Errorf("%w: got=%d want=%d", ErrInvalidDownstreamHintLength, len(payload), downstreamHintPayloadLen)
		}
		h := DownstreamHint{
			FirstMissingSN: binary.BigEndian.Uint32(payload[1:5]),
			HighestSentSN:  binary.BigEndian.Uint32(payload[5:9]),
			SuggestedCount: binary.BigEndian.Uint16(payload[9:11]),
			HintTTLms:      binary.BigEndian.Uint16(payload[11:13]),
		}
		if h.HintTTLms == 0 {
			return 0, nil, DownstreamHint{}, ErrInvalidDownstreamHintTTL
		}
		return flag, nil, h, nil
	default:
		return 0, nil, DownstreamHint{}, fmt.Errorf("%w: 0x%02x", ErrUnknownDownstreamFlag, flag)
	}
}

