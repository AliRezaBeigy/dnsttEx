// Downstream replay buffer for server-side KCP: stores recent PUSH payloads by
// sequence number so explicit resend requests (NREQ) can re-encode segments.

package kcp

import (
	"encoding/binary"
	"sync"
)

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

// resolveWireSN maps a 16-bit-on-wire sequence number to the full uint32 key used in bySN.
// When the client is stuck at a low rcv_nxt but the server has advanced snd_nxt far ahead,
// expandSN16(snd_nxt, wire) picks the wrong lap (e.g. 65536 instead of 0); we scan laps in
// order and return the first sn present in the replay map with sn < sndNxt (when sndNxt > 0).
// captureOutboundKCPPushes walks one or more concatenated dnstt-compact KCP frames (as written
// by kcp.flush into the output buffer) and records each IKCP_CMD_PUSH payload by sequence number.
//
// This duplicates the onOutboundPush hook so the replay map always matches what is about to be
// encrypted and sent, even if hook ordering or future refactors diverge. Sequence numbers use
// expandSN16 chained on expected next sn so multi-segment batches stay in the correct uint32 epoch.
func captureOutboundKCPPushes(r *downstreamReplay, data []byte) {
	if r == nil || len(data) < IKCP_OVERHEAD {
		return
	}
	nextSnAnchor := uint32(0)
	for len(data) >= IKCP_OVERHEAD {
		cmdFrg := data[2]
		cmd := (cmdFrg >> 6) + 81
		length := uint32(binary.LittleEndian.Uint16(data[10:12]))
		frameLen := int(IKCP_OVERHEAD + length)
		if len(data) < frameLen {
			break
		}
		if cmd == IKCP_CMD_PUSH {
			sn16 := uint32(binary.LittleEndian.Uint16(data[6:8]))
			sn := expandSN16(nextSnAnchor, sn16)
			payload := data[IKCP_OVERHEAD:frameLen]
			r.Add(sn, payload)
			nextSnAnchor = sn + 1
		}
		data = data[frameLen:]
	}
}

func (r *downstreamReplay) resolveWireSN(wire uint32, sndNxt uint32) (snFull uint32, ok bool) {
	if r == nil {
		return 0, false
	}
	w := wire & (kcpSNMod - 1)
	r.mu.Lock()
	defer r.mu.Unlock()
	const maxLaps = 128
	for lap := 0; lap < maxLaps; lap++ {
		sn := w + uint32(lap)*kcpSNMod
		if sndNxt != 0 && sn >= sndNxt {
			break
		}
		if _, ok := r.bySN[sn]; ok {
			return sn, true
		}
	}
	return 0, false
}
