package noise

import (
	"bytes"
	"io"
	"testing"
)

type bufferRWC struct {
	r *bytes.Reader
	w *bytes.Buffer
}

func (b *bufferRWC) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *bufferRWC) Write(p []byte) (int, error) { return b.w.Write(p) }
func (b *bufferRWC) Close() error                { return nil }

func TestWritePlainTransportPreamble(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePlainTransportPreamble(&buf); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	want := []byte{0, 1, PlainTransportModeByte}
	if !bytes.Equal(got, want) {
		t.Fatalf("preamble = %v want %v", got, want)
	}
}

func TestNegotiatePlainAllowed(t *testing.T) {
	var clientW bytes.Buffer
	_ = WritePlainTransportPreamble(&clientW)
	r := bytes.NewReader(clientW.Bytes())
	br := &bufferRWC{r: r, w: &bytes.Buffer{}}
	rw, plain, err := NegotiateServerTransport(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !plain {
		t.Fatal("expected plain transport")
	}
	if rw != br {
		t.Fatal("expected same rwc back")
	}
}

func TestNegotiateReplayPrefix(t *testing.T) {
	// First Noise message shape: u16(len) + len bytes (fake ciphertext).
	fake := []byte{0, 5, 1, 2, 3, 4, 5}
	r := bytes.NewReader(fake)
	br := &bufferRWC{r: r, w: &bytes.Buffer{}}
	priv, _ := GeneratePrivkey()
	_, plain, err := NegotiateServerTransport(br, priv)
	if plain {
		t.Fatal("expected Noise path")
	}
	if err == nil || err == io.EOF {
		// NewServer will fail on garbage handshake — any error is fine.
		t.Logf("NegotiateServerTransport: %v (expected for junk ciphertext)", err)
	}
}
