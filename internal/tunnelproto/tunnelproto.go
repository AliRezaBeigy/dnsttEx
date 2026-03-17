// Package tunnelproto defines the per-stream framing for socks tunnel mode.
package tunnelproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	TypeTCP byte = 0x01
	TypeUDP byte = 0x02
)

const (
	AckOK   byte = 0x00
	AckFail byte = 0x01
)

const (
	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04
)

// MaxUDPFrame is the maximum UDP payload size per framed message on the stream.
const MaxUDPFrame = 65507

var (
	ErrBadAddress    = errors.New("tunnelproto: invalid address encoding")
	ErrFrameTooLarge = errors.New("tunnelproto: UDP frame too large")
)

// WriteTCPOpen writes a TCP open request (type + SOCKS5-style destination).
func WriteTCPOpen(w io.Writer, host string, port uint16) error {
	return writeOpen(w, TypeTCP, host, port)
}

// WriteUDPOpen writes a UDP open request.
func WriteUDPOpen(w io.Writer, host string, port uint16) error {
	return writeOpen(w, TypeUDP, host, port)
}

func writeOpen(w io.Writer, typ byte, host string, port uint16) error {
	buf, err := encodeAddr(host, port)
	if err != nil {
		return err
	}
	_, err = w.Write(append([]byte{typ}, buf...))
	return err
}

func encodeAddr(host string, port uint16) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b := make([]byte, 1+4+2)
			b[0] = atypIPv4
			copy(b[1:], ip4)
			binary.BigEndian.PutUint16(b[5:], port)
			return b, nil
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, ErrBadAddress
		}
		b := make([]byte, 1+16+2)
		b[0] = atypIPv6
		copy(b[1:], ip16)
		binary.BigEndian.PutUint16(b[17:], port)
		return b, nil
	}
	if len(host) > 255 || len(host) == 0 {
		return nil, ErrBadAddress
	}
	b := make([]byte, 1+1+len(host)+2)
	b[0] = atypDomain
	b[1] = byte(len(host))
	copy(b[2:], host)
	binary.BigEndian.PutUint16(b[2+len(host):], port)
	return b, nil
}

// ReadOpen reads the first byte (type) and destination; returns "tcp"/"udp", host:port string.
func ReadOpen(r io.Reader) (network, addr string, err error) {
	var typ [1]byte
	if _, err = io.ReadFull(r, typ[:]); err != nil {
		return "", "", err
	}
	host, port, err := readSOCKSAddr(r)
	if err != nil {
		return "", "", err
	}
	switch typ[0] {
	case TypeTCP:
		return "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), nil
	case TypeUDP:
		return "udp", net.JoinHostPort(host, strconv.Itoa(int(port))), nil
	default:
		return "", "", fmt.Errorf("tunnelproto: unknown open type 0x%02x", typ[0])
	}
}

func readSOCKSAddr(r io.Reader) (host string, port uint16, err error) {
	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case atypIPv4:
		var b [4 + 2]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:4]).String(), binary.BigEndian.Uint16(b[4:]), nil
	case atypIPv6:
		var b [16 + 2]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:16]).String(), binary.BigEndian.Uint16(b[16:]), nil
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, ErrBadAddress
		}
		domain := make([]byte, int(l[0])+2)
		if _, err = io.ReadFull(r, domain); err != nil {
			return "", 0, err
		}
		return string(domain[:l[0]]), binary.BigEndian.Uint16(domain[l[0]:]), nil
	default:
		return "", 0, ErrBadAddress
	}
}

// WriteAck writes dial result to the stream.
func WriteAck(w io.Writer, ok bool) error {
	b := AckFail
	if ok {
		b = AckOK
	}
	_, err := w.Write([]byte{b})
	return err
}

// ReadAck reads one byte dial ack.
func ReadAck(r io.Reader) (ok bool, err error) {
	var b [1]byte
	if _, err = io.ReadFull(r, b[:]); err != nil {
		return false, err
	}
	switch b[0] {
	case AckOK:
		return true, nil
	case AckFail:
		return false, nil
	default:
		return false, fmt.Errorf("tunnelproto: bad ack 0x%02x", b[0])
	}
}

// WriteUDPFrame writes length-prefixed UDP payload (big-endian uint32).
func WriteUDPFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxUDPFrame {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadUDPFrame reads one framed UDP payload.
func ReadUDPFrame(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxUDPFrame {
		return nil, ErrFrameTooLarge
	}
	if uint32(cap(buf)) < n {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
