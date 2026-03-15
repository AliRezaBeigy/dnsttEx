// HTTP and SOCKS5 stream description for client-edge logging (DNSTT_RX_DATA / DNSTT_TX_DATA).
// See dns.go for package documentation.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// describeHTTPRequest parses the start of stream as an HTTP request and returns
// a one-line description (e.g. "HTTP GET /path HTTP/1.1 Host: example.com").
// Returns empty string if stream does not look like an HTTP request.
func describeHTTPRequest(stream []byte) string {
	line, rest := cutLine(stream)
	if len(line) == 0 {
		return ""
	}
	// Request line: METHOD URI HTTP/1.x
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(strings.ToUpper(parts[2]), "HTTP/") {
		return ""
	}
	method := strings.ToUpper(parts[0])
	uri := parts[1]
	reqLine := fmt.Sprintf("HTTP %s %s %s", method, uri, parts[2])
	host := findHTTPHeader(rest, "Host")
	if host != "" {
		return reqLine + " Host: " + host
	}
	return reqLine
}

// describeHTTPResponse parses the start of stream as an HTTP response and
// returns a one-line description (e.g. "HTTP/1.1 200 OK Content-Length: 123").
// Returns empty string if stream does not look like an HTTP response.
func describeHTTPResponse(stream []byte) string {
	line, rest := cutLine(stream)
	if len(line) == 0 {
		return ""
	}
	// Status line: HTTP/1.x CODE reason
	if !bytes.HasPrefix(line, []byte("HTTP/")) {
		return ""
	}
	statusLine := string(line)
	cl := findHTTPHeader(rest, "Content-Length")
	if cl != "" {
		return statusLine + " Content-Length: " + cl
	}
	return statusLine
}

// cutLine returns the first line (without \r\n or \n) and the rest of buf.
func cutLine(buf []byte) (line []byte, rest []byte) {
	for i := 0; i < len(buf); i++ {
		if buf[i] == '\n' {
			line = buf[:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			rest = buf[i+1:]
			return line, rest
		}
	}
	return buf, nil
}

// findHTTPHeader looks for "Key: value" in buf (headers section), case-insensitive key.
// Stops at first empty line (end of headers).
func findHTTPHeader(buf []byte, key string) string {
	keyLower := strings.ToLower(key)
	for len(buf) > 0 {
		line, next := cutLine(buf)
		if len(line) == 0 {
			return "" // end of headers
		}
		if i := bytes.IndexByte(line, ':'); i > 0 {
			k := strings.TrimSpace(string(line[:i]))
			if strings.ToLower(k) == keyLower {
				return strings.TrimSpace(string(line[i+1:]))
			}
		}
		buf = next
	}
	return ""
}

// FormatDownstreamForSocksLog returns a short parsed description of downstream
// data (SOCKS5 reply, HTTP response, or relay length). Used for client-edge
// logging in main_session.go (incoming/outgoing to local app) and tunnel-layer DNSTT_RX_DATA logs.
func FormatDownstreamForSocksLog(stream []byte) string {
	if len(stream) == 0 {
		return "0 B"
	}
	// SOCKS5 reply: VER=0x05 REP RSV ATYP BND.ADDR BND.PORT
	if len(stream) >= 4 && stream[0] == 0x05 {
		rep := stream[1]
		repStr := "ok"
		switch rep {
		case 0x00:
			repStr = "ok"
		case 0x01:
			repStr = "general failure"
		case 0x02:
			repStr = "not allowed"
		case 0x03:
			repStr = "network unreachable"
		case 0x04:
			repStr = "host unreachable"
		case 0x05:
			repStr = "connection refused"
		case 0x07:
			repStr = "command not supported"
		case 0x08:
			repStr = "address type not supported"
		default:
			repStr = fmt.Sprintf("rep=%d", rep)
		}
		atyp := stream[3]
		var bound string
		var consumed int
		switch atyp {
		case 0x01: // IPv4
			if len(stream) >= 10 {
				bound = net.IP(stream[4:8]).String()
				port := binary.BigEndian.Uint16(stream[8:10])
				bound = net.JoinHostPort(bound, strconv.Itoa(int(port)))
				consumed = 10
			} else {
				bound = "?"
				consumed = 4
			}
		case 0x03: // domain
			if len(stream) >= 5 {
				dLen := int(stream[4])
				if len(stream) >= 5+dLen+2 {
					bound = string(stream[5 : 5+dLen])
					port := binary.BigEndian.Uint16(stream[5+dLen : 7+dLen])
					bound = net.JoinHostPort(bound, strconv.Itoa(int(port)))
					consumed = 7 + dLen
				} else {
					bound = "?"
					consumed = 5
				}
			} else {
				bound = "?"
				consumed = 4
			}
		case 0x04: // IPv6
			if len(stream) >= 22 {
				bound = net.IP(stream[4:20]).String()
				port := binary.BigEndian.Uint16(stream[20:22])
				bound = net.JoinHostPort(bound, strconv.Itoa(int(port)))
				consumed = 22
			} else {
				bound = "?"
				consumed = 4
			}
		default:
			bound = "?"
			consumed = 4
		}
		s := fmt.Sprintf("SOCKS5 reply %s bound=%s", repStr, bound)
		if consumed < len(stream) {
			trailing := stream[consumed:]
			if desc := describeHTTPResponse(trailing); desc != "" {
				s += " | " + desc
			} else {
				s += fmt.Sprintf(" + %d B data", len(trailing))
			}
		}
		return s
	}
	if desc := describeHTTPResponse(stream); desc != "" {
		return desc
	}
	return fmt.Sprintf("relay %d B", len(stream))
}

// FormatUpstreamForSocksLog returns a short parsed description of upstream
// data (SOCKS5 greeting/CONNECT, HTTP request, or relay length). Used for
// client-edge logging in main_session.go and tunnel-layer DNSTT_TX_DATA logs.
func FormatUpstreamForSocksLog(stream []byte) string {
	if len(stream) == 0 {
		return "0 B"
	}
	// SOCKS5 CONNECT request: VER=0x05 CMD=0x01 RSV=0x00 ATYP DST.ADDR DST.PORT
	if len(stream) >= 4 && stream[0] == 0x05 && stream[1] == 0x01 && stream[2] == 0x00 {
		atyp := stream[3]
		var dest string
		var consumed int
		switch atyp {
		case 0x01: // IPv4
			if len(stream) >= 10 {
				dest = net.IP(stream[4:8]).String()
				port := binary.BigEndian.Uint16(stream[8:10])
				dest = net.JoinHostPort(dest, strconv.Itoa(int(port)))
				consumed = 10
			} else {
				dest = "?"
				consumed = 4
			}
		case 0x03: // domain
			if len(stream) >= 5 {
				dLen := int(stream[4])
				if len(stream) >= 5+dLen+2 {
					dest = string(stream[5 : 5+dLen])
					port := binary.BigEndian.Uint16(stream[5+dLen : 7+dLen])
					dest = net.JoinHostPort(dest, strconv.Itoa(int(port)))
					consumed = 7 + dLen
				} else {
					dest = "?"
					consumed = 5
				}
			} else {
				dest = "?"
				consumed = 4
			}
		case 0x04: // IPv6
			if len(stream) >= 22 {
				dest = net.IP(stream[4:20]).String()
				port := binary.BigEndian.Uint16(stream[20:22])
				dest = net.JoinHostPort(dest, strconv.Itoa(int(port)))
				consumed = 22
			} else {
				dest = "?"
				consumed = 4
			}
		default:
			dest = "?"
			consumed = 4
		}
		s := fmt.Sprintf("SOCKS5 CONNECT %s", dest)
		if consumed < len(stream) {
			trailing := stream[consumed:]
			if desc := describeHTTPRequest(trailing); desc != "" {
				s += " | " + desc
			} else {
				s += fmt.Sprintf(" + %d B data", len(trailing))
			}
		}
		return s
	}
	// SOCKS5 greeting: VER=0x05 NMETHODS METHODS...
	if len(stream) >= 2 && stream[0] == 0x05 {
		nMethods := int(stream[1])
		consumed := 2 + nMethods
		if consumed > len(stream) {
			consumed = len(stream)
		}
		s := fmt.Sprintf("SOCKS5 greeting %d method(s)", nMethods)
		if consumed < len(stream) {
			trailing := stream[consumed:]
			if desc := describeHTTPRequest(trailing); desc != "" {
				s += " | " + desc
			} else {
				s += fmt.Sprintf(" + %d B data", len(trailing))
			}
		}
		return s
	}
	if desc := describeHTTPRequest(stream); desc != "" {
		return desc
	}
	return fmt.Sprintf("relay %d B", len(stream))
}
