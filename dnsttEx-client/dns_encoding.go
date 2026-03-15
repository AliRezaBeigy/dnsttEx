// Base36 encoding and small helpers for DNS tunnel payload in QNAME.
// See dns.go for DNSPacketConn and package documentation.

package main

import (
	"errors"
)

// Base36 uses 0-9a-v (32 of 36 symbols); 5 bits/symbol so expansion = 8/5, same as Base32.
// Server decodes case-insensitively for QNAME randomization. Alphabet is DNS-safe.
const base36Alphabet = "0123456789abcdefghijklmnopqrstuv"

func base36EncodedLen(n int) int { return (n*8 + 4) / 5 }

func base36Encode(dst, src []byte) {
	for i, bitOffset := 0, 0; i < len(dst); i++ {
		byteIdx := bitOffset / 8
		bits := bitOffset % 8
		var v byte
		if byteIdx < len(src) {
			v = src[byteIdx] << bits
			if byteIdx+1 < len(src) {
				v |= src[byteIdx+1] >> (8 - bits)
			}
		}
		dst[i] = base36Alphabet[v>>3]
		bitOffset += 5
	}
}

var errBase36Decode = errors.New("invalid base36")

func base36Decode(dst, src []byte) error {
	bits := 0
	acc := uint(0)
	out := 0
	for _, c := range src {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'z':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'Z':
			v = c - 'A' + 10
		default:
			return errBase36Decode
		}
		if v >= 32 {
			return errBase36Decode
		}
		acc = acc<<5 | uint(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if out < len(dst) {
				dst[out] = byte(acc >> bits)
			}
			out++
		}
	}
	return nil
}

func base36DecodedLen(n int) int { return n * 5 / 8 }

func truncHex(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return b[:max]
}
