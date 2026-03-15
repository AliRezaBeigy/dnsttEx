//go:build integration

package integration_test

import (
	"bytes"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// mtuDiscoveryLogPattern matches MTU discovery log from client stderr.
var mtuDiscoveryLogPattern = regexp.MustCompile(`MTU discovery: .* → max response wire (\d+) bytes, max query QNAME (\d+) bytes`)

// parseMTUDiscoveryFromStderr reads stderrBuf and returns (serverMTU, clientMTU, true) if a line matches.
// Returns (0, 0, false) if not found.
func parseMTUDiscoveryFromStderr(stderrBuf *bytes.Buffer) (serverMTU, clientMTU int, ok bool) {
	sub := mtuDiscoveryLogPattern.FindSubmatch(stderrBuf.Bytes())
	if len(sub) != 3 {
		return 0, 0, false
	}
	serverMTU, _ = strconv.Atoi(string(sub[1]))
	clientMTU, _ = strconv.Atoi(string(sub[2]))
	return serverMTU, clientMTU, true
}

// waitForMTUDiscovery polls stderrBuf for the MTU discovery log line until timeout.
func waitForMTUDiscovery(t testing.TB, stderrBuf *bytes.Buffer, timeout time.Duration) (serverMTU, clientMTU int) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s, c, ok := parseMTUDiscoveryFromStderr(stderrBuf); ok {
			return s, c
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("did not see MTU discovery log line in client stderr within %v", timeout)
	return 0, 0
}
