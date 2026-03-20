package noise

import (
	"encoding/binary"
	"fmt"
	"io"
)

// PlainTransportModeByte selects plaintext smux directly on the KCP stream (no
// Noise). It is sent after a big-endian u16 length of 1 so it cannot collide
// with a valid Noise NK first message (that payload is never 1 byte).
const PlainTransportModeByte byte = 0x02

// WritePlainTransportPreamble writes the 3-byte selector. Caller then uses
// smux.Client/Server on the same ReadWriteCloser without wrapping in Noise.
func WritePlainTransportPreamble(w io.Writer) error {
	var hdr [3]byte
	binary.BigEndian.PutUint16(hdr[:2], 1)
	hdr[2] = PlainTransportModeByte
	_, err := w.Write(hdr[:])
	return err
}

type prefixReplayRWC struct {
	inner  io.ReadWriteCloser
	prefix []byte
}

func (p *prefixReplayRWC) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.inner.Read(b)
}

func (p *prefixReplayRWC) Write(b []byte) (int, error) {
	return p.inner.Write(b)
}

func (p *prefixReplayRWC) Close() error {
	return p.inner.Close()
}

// NegotiateServerTransport reads the first Noise-style length-prefixed chunk
// (big-endian u16 + body). If it is the plain-transport sentinel, returns
// (rwc, true, nil). Otherwise the bytes are replayed to Noise.NewServer.
func NegotiateServerTransport(rwc io.ReadWriteCloser, privkey []byte) (io.ReadWriteCloser, bool, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(rwc, lenBuf[:]); err != nil {
		return nil, false, err
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen == 1 {
		var mode [1]byte
		if _, err := io.ReadFull(rwc, mode[:]); err != nil {
			return nil, false, err
		}
		if mode[0] == PlainTransportModeByte {
			return rwc, true, nil
		}
		return nil, false, fmt.Errorf("invalid transport preamble: length=1 mode=%02x", mode[0])
	}
	body := make([]byte, msgLen)
	if _, err := io.ReadFull(rwc, body); err != nil {
		return nil, false, err
	}
	replay := make([]byte, 0, 2+len(body))
	replay = append(replay, lenBuf[:]...)
	replay = append(replay, body...)
	nw, err := NewServer(&prefixReplayRWC{inner: rwc, prefix: replay}, privkey)
	if err != nil {
		return nil, false, err
	}
	return nw, false, nil
}
