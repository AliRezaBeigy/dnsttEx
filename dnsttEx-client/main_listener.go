// TCP listener and stream handling (run, handle, copy with logging).
// See main.go for package documentation; sessionManager in main_session.go.

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"dnsttEx/dns"

	socks5 "github.com/things-go/go-socks5"
	"github.com/xtaci/smux"
)

// Logging constants for DNSTT_LOG_RX_DATA.
const (
	peekSize              = 4096
	logFirstChunks        = 5
	minChunkBytesForCount = 4
)

const firstDownstreamGatherMin = 10

// copyUpstreamWithLog copies from local to stream and, when DNSTT_LOG_RX_DATA is set,
// logs the first few chunks using FormatUpstreamForSocksLog.
func copyUpstreamWithLog(stream *smux.Stream, local *net.TCPConn, conv uint32, streamID uint32) (int64, error) {
	buf := make([]byte, peekSize)
	var total int64
	logCount := 0
	for logCount < logFirstChunks {
		n, err := local.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if dnsttLogRxData() {
				desc := FormatUpstreamForSocksLog(chunk)
				log.Printf("DNSTT_CLIENT_UPSTREAM stream %08x:%d | %s", conv, streamID, desc)
				if n >= minChunkBytesForCount {
					logCount++
				}
			}
			if _, werr := stream.Write(chunk); werr != nil {
				return total + int64(n), werr
			}
			total += int64(n)
			continue
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		break
	}
	copied, err := io.Copy(stream, local)
	return total + copied, err
}

// copyDownstreamWithLog copies from stream to local and, when DNSTT_LOG_RX_DATA is set,
// logs the first few chunks using FormatDownstreamForSocksLog.
func copyDownstreamWithLog(local *net.TCPConn, stream *smux.Stream, conv uint32, streamID uint32) (int64, error) {
	buf := make([]byte, peekSize)
	var total int64
	logCount := 0
	for logCount < logFirstChunks {
		n, err := stream.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if dnsttLogRxData() && logCount == 0 && n < firstDownstreamGatherMin && n < len(buf) {
				stream.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				nn, _ := stream.Read(buf[n:])
				stream.SetReadDeadline(time.Time{})
				if nn > 0 {
					chunk = buf[:n+nn]
					n += nn
				}
			}
			if dnsttLogRxData() {
				desc := FormatDownstreamForSocksLog(chunk)
				log.Printf("DNSTT_CLIENT_DOWNSTREAM stream %08x:%d | %s", conv, streamID, desc)
				if len(chunk) >= minChunkBytesForCount {
					logCount++
				}
			}
			if _, werr := local.Write(chunk); werr != nil {
				return total + int64(len(chunk)), werr
			}
			total += int64(len(chunk))
			continue
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		break
	}
	copied, err := io.Copy(local, stream)
	return total + copied, err
}

func handle(local *net.TCPConn, sm *sessionManager) error {
	stream, conv, err := sm.openStream()
	if err != nil {
		return fmt.Errorf("opening stream: %v", err)
	}
	defer func() {
		log.Printf("connection closed: stream %08x:%d — ended", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := copyUpstreamWithLog(stream, local, conv, stream.ID())
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("connection closed: stream %08x:%d — local→tunnel write failed: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
	}()
	go func() {
		defer wg.Done()
		_, err := copyDownstreamWithLog(local, stream, conv, stream.ID())
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("connection closed: stream %08x:%d — tunnel→local read failed (remote may have closed): %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

// packetConnWithDone is implemented by PacketConns that signal when they are closed.
type packetConnWithDone interface {
	net.PacketConn
	Done() <-chan struct{}
}

type kcpMTUHint interface {
	KCPMTUHint() int
}

func clientKCPMTU(domain dns.Name, pconn net.PacketConn) (int, error) {
	capacity := nameCapacity(domain)
	// v2 query framing adds 3 bytes ahead of packet framing:
	// [marker 0xFD][hint_hi][hint_lo].
	overhead := 8 + 1 + 2 + 1 + numPadding + 1
	maxPayloadInName := capacity - overhead
	if maxPayloadInName < 1 {
		return 0, fmt.Errorf("domain %s leaves no room for payload (capacity %d)", domain, capacity)
	}
	mtu := maxPacketSize
	if maxPayloadInName < mtu {
		mtu = maxPayloadInName
	}
	if hintConn, ok := pconn.(kcpMTUHint); ok {
		if hint := hintConn.KCPMTUHint(); hint >= minKCPMTU && hint < mtu {
			mtu = hint
		} else if hint > 0 && hint < minKCPMTU && dnsttTrace() {
			log.Printf("DNSTT_TRACE: client run: ignoring request-path MTU hint %d below KCP minimum %d", hint, minKCPMTU)
		}
	}
	if mtu < minKCPMTU {
		return 0, fmt.Errorf("tunnel MTU %d bytes is below KCP minimum (%d); use a shorter domain or larger path MTU", mtu, minKCPMTU)
	}
	return mtu, nil
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	mtu, err := clientKCPMTU(domain, pconn)
	if err != nil {
		return err
	}
	log.Printf("Tunnel MTU: %d bytes", mtu)

	sm := newSessionManager(pubkey, domain, remoteAddr, pconn, mtu)
	defer sm.closeSession("tunnel shutting down")

	if dpc, ok := pconn.(packetConnWithDone); ok {
		acceptCh := make(chan net.Conn, 1)
		go func() {
			for {
				local, err := ln.Accept()
				if err != nil {
					close(acceptCh)
					return
				}
				select {
				case acceptCh <- local:
				case <-dpc.Done():
					log.Printf("connection closed: tunnel transport closed (rejecting new connection)")
					local.Close()
					close(acceptCh)
					return
				}
			}
		}()
		for {
			select {
			case <-dpc.Done():
				return nil
			case local, ok := <-acceptCh:
				if !ok {
					return nil
				}
				go func(c net.Conn) {
					defer c.Close()
					if err := handle(c.(*net.TCPConn), sm); err != nil {
						log.Printf("handle: %v", err)
					}
				}(local)
			}
		}
	}

	for {
		local, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sm)
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

// runSocks runs SOCKS5 on localAddr; each CONNECT/UDP relay uses the DNS tunnel (server must use -tunnel socks).
func runSocks(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	mtu, err := clientKCPMTU(domain, pconn)
	if err != nil {
		return err
	}
	log.Printf("Tunnel MTU: %d bytes (SOCKS5 on %s)", mtu, localAddr.String())

	sm := newSessionManager(pubkey, domain, remoteAddr, pconn, mtu)
	defer sm.closeSession("tunnel shutting down")

	t := newSocksTunnel(sm)
	opts := []socks5.Option{
		socks5.WithConnectHandle(t.connectHandle),
		socks5.WithAssociateHandle(t.associateHandle),
	}
	if ip := localAddr.IP; len(ip) > 0 && !ip.IsUnspecified() {
		opts = append(opts, socks5.WithBindIP(ip))
	}
	srv := socks5.NewServer(opts...)

	l, err := net.Listen("tcp", localAddr.String())
	if err != nil {
		return fmt.Errorf("SOCKS5 listen: %v", err)
	}
	defer l.Close()
	log.Printf("SOCKS5 listening on %s (tunnel socks mode)", l.Addr())

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(l) }()

	if dpc, ok := pconn.(packetConnWithDone); ok {
		select {
		case <-dpc.Done():
			_ = l.Close()
			<-errCh
			return nil
		case err := <-errCh:
			return err
		}
	}
	return <-errCh
}
