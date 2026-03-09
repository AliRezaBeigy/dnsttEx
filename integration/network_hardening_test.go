//go:build integration

package integration_test

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestTunnelSurvivesModerateDNSLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping loss test in short mode")
	}
	clientEnv := map[string]string{"DNSTT_MTU_PROBE_TIMEOUT": "1s"}
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newChaosUDPRelay(t, addr, 11, 9, 0, 0)
		},
		&bytes.Buffer{}, clientEnv)

	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(90 * time.Second))

	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write over lossy path: %v", err)
	}
	recv := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read over lossy path: %v", err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("echo mismatch over lossy DNS path")
	}
}

func TestTunnelSurvivesDelayedAndDuplicatedResponses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping delay/duplicate test in short mode")
	}
	clientEnv := map[string]string{"DNSTT_MTU_PROBE_TIMEOUT": "1s"}
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newChaosUDPRelay(t, addr, 0, 0, 4, 120*time.Millisecond)
		},
		&bytes.Buffer{}, clientEnv)

	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte((255 - i) % 256)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write over delayed path: %v", err)
	}
	recv := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read over delayed path: %v", err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("echo mismatch over delayed/duplicated DNS path")
	}
}

func TestTunnelSurvivesOccasionalMalformedResponses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping malformed-response test in short mode")
	}
	clientEnv := map[string]string{"DNSTT_MTU_PROBE_TIMEOUT": "1s"}
	h := newTunnelHarnessWithRelayAndStderr(t, globalServerBin, globalClientBin,
		func(addr string) udpRelay {
			return newTruncatingEveryNthUDPRelay(t, addr, 7, 24)
		},
		&bytes.Buffer{}, clientEnv)

	conn := h.dialTunnel(t)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte((i * 17) % 256)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write over malformed-response path: %v", err)
	}
	recv := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read over malformed-response path: %v", err)
	}
	if !bytes.Equal(payload, recv) {
		t.Fatal("echo mismatch over malformed-response DNS path")
	}
}
