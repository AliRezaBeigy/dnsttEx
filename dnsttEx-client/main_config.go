// Configuration constants and environment helpers for dnstt-client.
// See main.go for package documentation.

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"dnsttEx/noise"
)

// Session and MTU tuning constants.
const (
	idleTimeout = 2 * time.Minute
	// mtuProbeNXDOMAINRetries: when request-size MTU probe gets NXDOMAIN, retry this many times before giving up.
	mtuProbeNXDOMAINRetries = 3
	// mtuProbeSuccessesRequired: a candidate size is accepted only after this many successful probe exchanges.
	mtuProbeSuccessesRequired = 3
	// mtuProbeAfterTimeoutRetries: per trial, after a read timeout, repeat send+read this many extra times (1 = one retry).
	mtuProbeAfterTimeoutRetries = 1
	// minKCPMTU is the minimum MTU KCP accepts (IKCP_OVERHEAD+1 = 13).
	// Low-MTU DNS paths (e.g. 128-byte requests) need MTU as low as ~42
	// so each KCP segment fits inside one DNS query.
	minKCPMTU = 13
)

// dnsttDebug returns true when DNSTT_DEBUG is set (for verbose PING/PONG and MTU discovery logs).
func dnsttDebug() bool { return os.Getenv("DNSTT_DEBUG") != "" }

// dnsttLogRxData enables DNS payload tracing: RX (answers) and TX (data sends only; idle polls not logged).
// Set DNSTT_LOG_RX_DATA=1. Lines: DNSTT_TX_DATA → (tunnel upstream), DNSTT_RX_* ← (downstream).
func dnsttLogRxData() bool { return os.Getenv("DNSTT_LOG_RX_DATA") != "" }

// dnsttTrace returns true when DNSTT_TRACE is set (for full path tracing to diagnose failures).
func dnsttTrace() bool { return os.Getenv("DNSTT_TRACE") != "" }

// mtuProbeTimeout returns the per-probe timeout for MTU discovery. Default 8s.
// Set DNSTT_MTU_PROBE_TIMEOUT to a duration (e.g. "2s", "1500ms") to use a shorter timeout
// (e.g. in integration tests where dropped probes would otherwise block 8s).
func mtuProbeTimeout() time.Duration {
	s := os.Getenv("DNSTT_MTU_PROBE_TIMEOUT")
	if s == "" {
		return 8 * time.Second
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 8 * time.Second
	}
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	return d
}

// dnsttDebugHexDump returns a hex dump of b for DNSTT_DEBUG logs. If len(b) > max, only the first max bytes are shown.
func dnsttDebugHexDump(b []byte, max int) string {
	const defaultMax = 512
	if max <= 0 {
		max = defaultMax
	}
	if len(b) <= max {
		return hex.Dump(b)
	}
	return hex.Dump(b[:max]) + fmt.Sprintf("\t... (%d bytes total)\n", len(b))
}

// stringSliceFlag is a flag.Value that collects repeated string flags into a slice.
type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}
