package main

import (
	"testing"

	"dnsttEx/dns"
)

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
