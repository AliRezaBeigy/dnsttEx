// Package turbotunnel is facilities for embedding packet-based reliability
// protocols inside other protocols.
//
// https://github.com/net4people/bbs/issues/9
package turbotunnel

import (
	"errors"
	"os"
	"strconv"
)

// QueueSize is the size of send and receive queues in QueuePacketConn and
// RemoteMap. Must be at least as large as the KCP window size to prevent
// silent drops from starving KCP retransmission.
// Override at process start with DNSTT_QUEUE_SIZE (e.g. 2048, 4096) for
// high-latency or lossy networks to reduce drops when KCP retransmits.
var QueueSize = 4096

func init() {
	if s := os.Getenv("DNSTT_QUEUE_SIZE"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 256 {
			const maxQueueSize = 65536
			if n > maxQueueSize {
				n = maxQueueSize
			}
			QueueSize = n
		}
	}
}

var errClosedPacketConn = errors.New("operation on closed connection")
var errNotImplemented = errors.New("not implemented")

// DummyAddr is a placeholder net.Addr, for when a programming interface
// requires a net.Addr but there is none relevant. All DummyAddrs compare equal
// to each other.
type DummyAddr struct{}

func (addr DummyAddr) Network() string { return "dummy" }
func (addr DummyAddr) String() string  { return "dummy" }
