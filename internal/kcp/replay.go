// Downstream replay buffer for server-side KCP: stores recent PUSH payloads by
// sequence number so explicit resend requests (NREQ) can re-encode segments.

package kcp

import "sync"

const (
	defaultReplayMaxEntries = 2048
	defaultReplayMaxBytes   = 2048 * 1024
)

type downstreamReplay struct {
	mu sync.Mutex

	maxEntries int
	maxBytes   int
	curBytes   int

	bySN  map[uint32][]byte
	order []uint32
}

func newDownstreamReplay() *downstreamReplay {
	return &downstreamReplay{
		maxEntries: defaultReplayMaxEntries,
		maxBytes:   defaultReplayMaxBytes,
		bySN:       make(map[uint32][]byte),
	}
}

func (r *downstreamReplay) Add(sn uint32, payload []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if old, ok := r.bySN[sn]; ok {
		r.curBytes -= len(old)
	} else {
		r.order = append(r.order, sn)
	}
	cp := append([]byte(nil), payload...)
	r.bySN[sn] = cp
	r.curBytes += len(cp)

	r.evictLocked()
}

func (r *downstreamReplay) evictLocked() {
	for (len(r.order) > r.maxEntries || r.curBytes > r.maxBytes) && len(r.order) > 0 {
		// Evict highest sn first. FIFO eviction removed the oldest (lowest) sns first,
		// which are exactly what a stalled client requests via NREQ (first missing sn).
		maxIdx := 0
		for i := 1; i < len(r.order); i++ {
			if _itimediff(r.order[i], r.order[maxIdx]) > 0 {
				maxIdx = i
			}
		}
		oldSN := r.order[maxIdx]
		r.order = append(r.order[:maxIdx], r.order[maxIdx+1:]...)
		if old, ok := r.bySN[oldSN]; ok {
			r.curBytes -= len(old)
			delete(r.bySN, oldSN)
		}
	}
}

// payloadForNREQ returns stored bytes for sn. ok is false if sn was never recorded.
// payload may have length 0 (valid KCP PUSH); callers must not treat empty as "missing".
func (r *downstreamReplay) payloadForNREQ(sn uint32) (payload []byte, ok bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.bySN[sn]
	return p, ok
}
