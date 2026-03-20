// SOCKS5 server for -tunnel socks mode using github.com/things-go/go-socks5.
// (golang.org/x/net/proxy is client-side only — it dials through SOCKS, it does not accept SOCKS clients.)

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"dnsttEx/internal/tunnelproto"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"github.com/xtaci/smux"
)

type socksTunnel struct {
	sm *sessionManager
}

func newSocksTunnel(sm *sessionManager) *socksTunnel {
	return &socksTunnel{sm: sm}
}

func addrSpecToHostPort(a statute.AddrSpec) (host string, port uint16) {
	if a.FQDN != "" {
		return a.FQDN, uint16(a.Port)
	}
	if a.IP != nil {
		return a.IP.String(), uint16(a.Port)
	}
	return "", 0
}

func addrSpecDialString(a statute.AddrSpec) string {
	h, p := addrSpecToHostPort(a)
	return net.JoinHostPort(h, strconv.Itoa(int(p)))
}

func (t *socksTunnel) connectHandle(ctx context.Context, w io.Writer, req *socks5.Request) error {
	addr := req.DestAddr.String()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		_ = socks5.SendReply(w, statute.RepAddrTypeNotSupported, nil)
		log.Printf("socks tcp parse dest %q: %v", addr, err)
		return err
	}
	p64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		_ = socks5.SendReply(w, statute.RepAddrTypeNotSupported, nil)
		log.Printf("socks tcp parse port %q from %q: %v", portStr, addr, err)
		return err
	}
	dest := net.JoinHostPort(host, strconv.Itoa(int(p64)))

	client := ""
	if req.RemoteAddr != nil {
		client = req.RemoteAddr.String()
	}
	log.Printf("socks: CONNECT %s from %s", dest, client)

	t0 := time.Now()
	stream, conv, err := t.sm.openStream()
	if err != nil {
		_ = socks5.SendReply(w, statute.RepServerFailure, nil)
		log.Printf("socks tcp open stream for %s: %v", dest, err)
		return err
	}
	// One outer KCP session ("begin session"); each SOCKS CONNECT is a new smux stream on top.
	log.Printf("begin stream %08x:%d (socks → %s) after %s", conv, stream.ID(), dest, time.Since(t0).Round(time.Millisecond))
	if err := tunnelproto.WriteTCPOpen(stream, host, uint16(p64)); err != nil {
		stream.Close()
		_ = socks5.SendReply(w, statute.RepServerFailure, nil)
		log.Printf("socks tcp %08x:%d send open %s: %v", conv, stream.ID(), dest, err)
		return err
	}
	ok, err := tunnelproto.ReadAck(stream)
	if err != nil {
		stream.Close()
		// Protocol/read failure while waiting for server dial ack is a tunnel/server
		// failure, not a destination reachability result.
		_ = socks5.SendReply(w, statute.RepServerFailure, nil)
		log.Printf("socks tcp %08x:%d read ack for %s: %v", conv, stream.ID(), dest, err)
		return err
	}
	if !ok {
		stream.Close()
		_ = socks5.SendReply(w, statute.RepHostUnreachable, nil)
		log.Printf("socks tcp %08x:%d remote rejected %s (ack fail)", conv, stream.ID(), dest)
		return fmt.Errorf("remote dial failed")
	}
	log.Printf("socks tcp %08x:%d connected %s", conv, stream.ID(), dest)

	clientConn, ok := w.(net.Conn)
	if !ok {
		stream.Close()
		log.Printf("socks tcp %08x:%d %s: expected net.Conn writer", conv, stream.ID(), dest)
		return fmt.Errorf("socks: expected net.Conn writer")
	}
	if err := socks5.SendReply(w, statute.RepSuccess, clientConn.LocalAddr()); err != nil {
		stream.Close()
		log.Printf("socks tcp %08x:%d send success reply for %s: %v", conv, stream.ID(), dest, err)
		return err
	}

	errCh := make(chan error, 2)
	go func() {
		_, e := io.Copy(clientConn, stream)
		if tcp, ok := clientConn.(*net.TCPConn); ok && e == nil {
			_ = tcp.CloseRead()
		}
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(stream, req.Reader)
		if tcp, ok := clientConn.(*net.TCPConn); ok && e == nil {
			_ = tcp.CloseWrite()
		}
		errCh <- e
	}()
	<-errCh
	<-errCh
	stream.Close()
	return nil
}

type udpAssocEntry struct {
	stream *smux.Stream
	dst    statute.AddrSpec
	client *net.UDPAddr
}

type udpAssociateRelay struct {
	sm      *sessionManager
	bindLn  *net.UDPConn
	mu      sync.Mutex
	streams map[string]*udpAssocEntry
}

func (t *socksTunnel) associateHandle(ctx context.Context, w io.Writer, req *socks5.Request) error {
	var udpAddr *net.UDPAddr
	if la, ok := req.LocalAddr.(*net.TCPAddr); ok {
		udpAddr = &net.UDPAddr{IP: la.IP, Port: 0}
	} else {
		udpAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	bindLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = socks5.SendReply(w, statute.RepServerFailure, nil)
		return err
	}
	if err := socks5.SendReply(w, statute.RepSuccess, bindLn.LocalAddr()); err != nil {
		bindLn.Close()
		return err
	}

	relay := &udpAssociateRelay{
		sm:      t.sm,
		bindLn:  bindLn,
		streams: make(map[string]*udpAssocEntry),
	}
	go func() {
		_, _ = io.Copy(io.Discard, req.Reader)
		bindLn.Close()
	}()

	buf := make([]byte, 65507)
	for {
		n, src, err := bindLn.ReadFromUDP(buf)
		if err != nil {
			relay.closeAllStreams()
			return nil
		}
		pkt := append([]byte(nil), buf[:n]...)
		pk, err := statute.ParseDatagram(pkt)
		if err != nil || pk.Frag != 0 {
			continue
		}
		key := src.String() + "|" + addrSpecDialString(pk.DstAddr)
		if err := relay.forwardDatagram(key, src, pk); err != nil {
			log.Printf("socks udp %s: %v", key, err)
		}
	}
}

func (r *udpAssociateRelay) forwardDatagram(key string, src *net.UDPAddr, pk statute.Datagram) error {
	r.mu.Lock()
	if ent := r.streams[key]; ent != nil {
		st := ent.stream
		r.mu.Unlock()
		return tunnelproto.WriteUDPFrame(st, pk.Data)
	}
	r.mu.Unlock()

	stream, _, err := r.sm.openStream()
	if err != nil {
		return err
	}
	host, port := addrSpecToHostPort(pk.DstAddr)
	if host == "" {
		stream.Close()
		return fmt.Errorf("bad destination")
	}
	if err := tunnelproto.WriteUDPOpen(stream, host, port); err != nil {
		stream.Close()
		return err
	}
	ok, err := tunnelproto.ReadAck(stream)
	if err != nil || !ok {
		stream.Close()
		return fmt.Errorf("udp tunnel open failed")
	}

	clientCopy := *src
	ent := &udpAssocEntry{stream: stream, dst: pk.DstAddr, client: &clientCopy}

	r.mu.Lock()
	if existing := r.streams[key]; existing != nil {
		r.mu.Unlock()
		stream.Close()
		return tunnelproto.WriteUDPFrame(existing.stream, pk.Data)
	}
	r.streams[key] = ent
	r.mu.Unlock()
	go r.pumpUDPBack(key, ent)
	return tunnelproto.WriteUDPFrame(stream, pk.Data)
}

func (r *udpAssociateRelay) pumpUDPBack(key string, ent *udpAssocEntry) {
	defer func() {
		ent.stream.Close()
		r.mu.Lock()
		delete(r.streams, key)
		r.mu.Unlock()
	}()
	buf := make([]byte, 65536)
	for {
		payload, err := tunnelproto.ReadUDPFrame(ent.stream, buf)
		if err != nil {
			return
		}
		dg, err := statute.NewDatagram(addrSpecDialString(ent.dst), payload)
		if err != nil {
			continue
		}
		if _, err := r.bindLn.WriteToUDP(dg.Bytes(), ent.client); err != nil {
			return
		}
	}
}

func (r *udpAssociateRelay) closeAllStreams() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.streams {
		e.stream.Close()
	}
	r.streams = make(map[string]*udpAssocEntry)
}
