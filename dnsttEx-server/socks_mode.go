package main

import (
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"dnsttEx/internal/tunnelproto"

	"github.com/xtaci/smux"
)

// handleSocksRelay reads tunnelproto open (TCP or UDP), dials the target, sends ack, then relays.
func handleSocksRelay(stream *smux.Stream, conv uint32) {
	netw, addr, err := tunnelproto.ReadOpen(stream)
	if err != nil {
		log.Printf("socks stream %08x:%d read open: %v", conv, stream.ID(), err)
		return
	}
	if netw == "tcp" {
		handleSocksTCPRelay(stream, addr, conv)
		return
	}
	if netw == "udp" {
		handleSocksUDPRelay(stream, addr, conv)
	}
}

func handleSocksTCPRelay(stream *smux.Stream, addr string, conv uint32) {
	dialer := net.Dialer{Timeout: upstreamDialTimeout}
	c, err := dialer.Dial("tcp", addr)
	if err != nil {
		_ = tunnelproto.WriteAck(stream, false)
		log.Printf("socks tcp %08x:%d dial %s: %v", conv, stream.ID(), addr, err)
		return
	}
	tcpc := c.(*net.TCPConn)
	if err := tunnelproto.WriteAck(stream, true); err != nil {
		tcpc.Close()
		return
	}
	defer tcpc.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, tcpc)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) && !strings.Contains(err.Error(), "closed") {
			log.Printf("socks tcp %08x:%d copy stream←remote: %v", conv, stream.ID(), err)
		}
		tcpc.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(tcpc, stream)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) && !strings.Contains(err.Error(), "closed") {
			log.Printf("socks tcp %08x:%d copy remote←stream: %v", conv, stream.ID(), err)
		}
		tcpc.CloseWrite()
	}()
	wg.Wait()
}

func handleSocksUDPRelay(stream *smux.Stream, addr string, conv uint32) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		_ = tunnelproto.WriteAck(stream, false)
		log.Printf("socks udp %08x:%d dial %s: %v", conv, stream.ID(), addr, err)
		return
	}
	if err := tunnelproto.WriteAck(stream, true); err != nil {
		c.Close()
		return
	}
	defer c.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	buf := make([]byte, 65536)
	go func() {
		defer wg.Done()
		for {
			payload, err := tunnelproto.ReadUDPFrame(stream, buf)
			if err != nil {
				return
			}
			if _, err := c.Write(payload); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		p := make([]byte, tunnelproto.MaxUDPFrame)
		for {
			n, err := c.Read(p)
			if err != nil {
				return
			}
			if err := tunnelproto.WriteUDPFrame(stream, p[:n]); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}
