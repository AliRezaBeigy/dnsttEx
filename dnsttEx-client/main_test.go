package main

import (
	"net"
	"strings"
	"testing"

	"dnsttEx/dns"
	"dnsttEx/noise"
	"dnsttEx/turbotunnel"
)

func TestRunRejectsLowMTU(t *testing.T) {
	// Domain with many long labels so nameCapacity is small and mtu < minKCPMTU.
	longLabel := strings.Repeat("a", 57)
	domain, err := dns.ParseName(longLabel + "." + longLabel + "." + longLabel + "." + longLabel)
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	capacity := nameCapacity(domain)
	overhead := 8 + 1 + numPadding + 1
	maxPayloadInName := capacity - overhead
	if maxPayloadInName >= minKCPMTU {
		t.Skipf("domain capacity gives mtu %d >= minKCPMTU %d; need longer domain", maxPayloadInName, minKCPMTU)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()

	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pconn.Close()
	privkey, _ := noise.GeneratePrivkey()
	pubkey := noise.PubkeyFromPrivkey(privkey)

	err = run(pubkey, domain, addr, turbotunnel.DummyAddr{}, pconn)
	if err == nil {
		t.Fatal("run: expected error for low MTU domain")
	}
	if !strings.Contains(err.Error(), "below KCP minimum") {
		t.Errorf("run: error %v does not mention KCP minimum", err)
	}
}

func TestNamePayloadCapacity(t *testing.T) {
	// Name-based encoding: ensure capacity fits ClientID + padding + at least one small packet.
	domain, _ := dns.ParseName("t.example.com")
	cap := nameCapacity(domain)
	minNeed := 8 + 1 + numPadding + 1 + 1
	if cap < minNeed {
		t.Errorf("nameCapacity(%s) = %d < %d", domain, cap, minNeed)
	}
	if maxPacketSize <= 0 || maxPacketSize >= 224 {
		t.Errorf("maxPacketSize %d invalid (must be 1..223)", maxPacketSize)
	}
}
