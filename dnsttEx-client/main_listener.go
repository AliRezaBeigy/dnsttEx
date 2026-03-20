// TCP listener and stream handling (run, handle, copy with logging).
// See main.go for package documentation; sessionManager in main_session.go.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
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
func copyUpstreamWithLog(stream *smux.Stream, local io.Reader, conv uint32, streamID uint32) (int64, error) {
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
	// While the tunnel session is being created, read from the local TCP in the
	// background. If the user aborts (e.g. curl Ctrl+C), we close the in-flight
	// KCP handshake so the next connection is not stuck behind createMu.
	quitEarlyRead := make(chan struct{})
	var earlyWG sync.WaitGroup
	var earlyMu sync.Mutex
	var earlyData []byte
	earlyWG.Add(1)
	go func() {
		defer earlyWG.Done()
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-quitEarlyRead:
				return
			default:
			}
			_ = local.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := local.Read(buf)
			_ = local.SetReadDeadline(time.Time{})
			if n > 0 {
				earlyMu.Lock()
				earlyData = append(earlyData, buf[:n]...)
				earlyMu.Unlock()
			}
			if err == nil {
				continue
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			sm.closeSession("local closed during tunnel setup")
			return
		}
	}()

	stream, conv, err := sm.openStream()
	close(quitEarlyRead)
	_ = local.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	earlyWG.Wait()

	if err != nil {
		return fmt.Errorf("opening stream: %v", err)
	}
	earlyMu.Lock()
	prefix := earlyData
	earlyMu.Unlock()
	upstream := io.MultiReader(bytes.NewReader(prefix), local)

	defer func() {
		log.Printf("connection closed: stream %08x:%d — ended", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := copyUpstreamWithLog(stream, upstream, conv, stream.ID())
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
	// Decoded upstream before Base36: clientID + v2 marker + hint + 1-byte
	// segment length + payload (same as DNSPacketConn.KCPMTUHint / sendLoop).
	overhead := 8 + 1 + 2 + 1 + numPadding
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
	if minOuter := minOuterTunnelMTUForKCP(); mtu < minOuter {
		return 0, fmt.Errorf("tunnel MTU %d bytes is below minimum (%d) for KCP over DNS with current FEC settings; use a shorter domain, a larger query path, or disable FEC (DNSTT_FEC_DATA=0 DNSTT_FEC_PARITY=0)", mtu, minOuter)
	}
	return mtu, nil
}

// applyTunnelWarmupEnv starts tunnel handshake per DNSTT_TUNNEL_WARMUP.
// socksMode: when true and env is unset, block until the tunnel exists before accepting
// SOCKS connections (browsers open many TCPs at once; async warmup often loses the race).
//   (unset) — SOCKS: sync warmup; TCP forward: async warmup in background
//   sync    — always block until handshake completes before serving
//   async   — always background warmup (SOCKS may stall parallel CONNECTs on first handshake)
//   off     — no warmup; first connection pays full handshake
func applyTunnelWarmupEnv(sm *sessionManager, socksMode bool) error {
	s := strings.ToLower(strings.TrimSpace(os.Getenv("DNSTT_TUNNEL_WARMUP")))
	switch s {
	case "off", "0", "false", "no":
		return nil
	case "sync":
		log.Printf("tunnel: DNSTT_TUNNEL_WARMUP=sync — completing handshake before SOCKS Accept loop")
		return sm.warmupTunnelSync()
	case "async":
		sm.warmupTunnelAsync()
		return nil
	default:
		if socksMode {
			log.Printf("tunnel: SOCKS default warmup — completing handshake before Accept (set DNSTT_TUNNEL_WARMUP=async to accept immediately)")
			return sm.warmupTunnelSync()
		}
		sm.warmupTunnelAsync()
		return nil
	}
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn, usePlain bool) error {
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

	sm := newSessionManager(pubkey, domain, remoteAddr, pconn, mtu, usePlain)
	defer sm.closeSession("tunnel shutting down")
	if err := applyTunnelWarmupEnv(sm, false); err != nil {
		return err
	}

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
func runSocks(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn, usePlain bool) error {
	defer pconn.Close()

	mtu, err := clientKCPMTU(domain, pconn)
	if err != nil {
		return err
	}
	log.Printf("Tunnel MTU: %d bytes (SOCKS5 on %s)", mtu, localAddr.String())

	sm := newSessionManager(pubkey, domain, remoteAddr, pconn, mtu, usePlain)
	defer sm.closeSession("tunnel shutting down")
	if err := applyTunnelWarmupEnv(sm, true); err != nil {
		return err
	}

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
