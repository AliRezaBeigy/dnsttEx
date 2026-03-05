package main

import (
	"testing"
)

func TestEDNSPayloadCapacity(t *testing.T) {
	// EDNS option carries binary payload; ensure we have room for ClientID + padding + at least one packet.
	minNeed := 8 + 1 + numPadding + 1 + 1 // clientID + padding byte + padding + length + 1 byte packet
	if maxPayloadPerQuery < minNeed {
		t.Errorf("maxPayloadPerQuery %d < %d", maxPayloadPerQuery, minNeed)
	}
	if maxPacketSize <= 0 || maxPacketSize >= 224 {
		t.Errorf("maxPacketSize %d invalid (must be 1..223)", maxPacketSize)
	}
}
