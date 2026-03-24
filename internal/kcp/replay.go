// Downstream replay buffer for server-side KCP: stores recent PUSH payloads by
// sequence number so explicit resend requests (NREQ) can re-encode segments.
// Entries are dropped when older than DNSTT_KCP_REPLAY_MAX_AGE (default 30s),
// and also when DNSTT_KCP_REPLAY_MAX_ENTRIES / DNSTT_KCP_REPLAY_MAX_BYTES are exceeded.

package kcp

import (
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	defaultReplayMaxEntries = 81920
	defaultReplayMaxBytes   = 80 * 1024 * 1024
	defaultReplayMaxAge     = 30 * time.Second
)

var (
	replayLimitsOnce      sync.Once
	replayMaxEntriesValue int
	replayMaxBytesValue   int
	replayMaxAgeValue     time.Duration
)

type downstreamReplay struct {
	mu sync.Mutex

	maxEntries int
	maxBytes   int
	maxAge     time.Duration
	curBytes   int

	bySN  map[uint32]replaySeg
	order []uint32
}

type replaySeg struct {
	payload []byte
	frg     uint8
	addedAt time.Time
}

func newDownstreamReplay() *downstreamReplay {
	maxEntries, maxBytes, maxAge := replayLimits()
	return &downstreamReplay{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		maxAge:     maxAge,
		bySN:       make(map[uint32]replaySeg),
	}
}

func replayLimits() (maxEntries int, maxBytes int, maxAge time.Duration) {
	replayLimitsOnce.Do(func() {
		replayMaxEntriesValue = defaultReplayMaxEntries
		replayMaxBytesValue = defaultReplayMaxBytes
		replayMaxAgeValue = defaultReplayMaxAge

		if s := os.Getenv("DNSTT_KCP_REPLAY_MAX_AGE"); s != "" {
			if d, err := time.ParseDuration(s); err == nil {
				if d <= 0 {
					replayMaxAgeValue = 0
				} else {
					replayMaxAgeValue = d
					if replayMaxAgeValue < time.Second {
						replayMaxAgeValue = time.Second
					}
					if replayMaxAgeValue > 24*time.Hour {
						replayMaxAgeValue = 24 * time.Hour
					}
				}
			}
		}

		if s := os.Getenv("DNSTT_KCP_REPLAY_MAX_ENTRIES"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				replayMaxEntriesValue = n
			}
		}
		if replayMaxEntriesValue < 2560 {
			replayMaxEntriesValue = 2560
		}
		if replayMaxEntriesValue > 2621440 {
			replayMaxEntriesValue = 2621440
		}

		if s := os.Getenv("DNSTT_KCP_REPLAY_MAX_BYTES"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				replayMaxBytesValue = n
			}
		}
		if replayMaxBytesValue < 2560*1024 {
			replayMaxBytesValue = 2560 * 1024
		}
		if replayMaxBytesValue > 5120*1024*1024 {
			replayMaxBytesValue = 5120 * 1024 * 1024
		}
	})
	return replayMaxEntriesValue, replayMaxBytesValue, replayMaxAgeValue
}

func (r *downstreamReplay) Add(sn uint32, frg uint8, payload []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if old, ok := r.bySN[sn]; ok {
		r.curBytes -= len(old.payload)
	} else {
		r.order = append(r.order, sn)
	}
	now := time.Now()
	cp := append([]byte(nil), payload...)
	r.bySN[sn] = replaySeg{
		payload: cp,
		frg:     frg,
		addedAt: now,
	}
	r.curBytes += len(cp)

	r.evictLocked(now)
}

// evictStaleLocked removes segments older than maxAge (wall clock). Skips if maxAge <= 0.
func (r *downstreamReplay) evictStaleLocked(now time.Time) {
	if r.maxAge <= 0 {
		return
	}
	cutoff := now.Add(-r.maxAge)
	newOrder := r.order[:0]
	for _, sn := range r.order {
		seg, ok := r.bySN[sn]
		if !ok {
			continue
		}
		if seg.addedAt.Before(cutoff) {
			r.curBytes -= len(seg.payload)
			delete(r.bySN, sn)
		} else {
			newOrder = append(newOrder, sn)
		}
	}
	r.order = newOrder
}

func (r *downstreamReplay) evictLocked(now time.Time) {
	r.evictStaleLocked(now)
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
			r.curBytes -= len(old.payload)
			delete(r.bySN, oldSN)
		}
	}
}

// payloadForNREQ returns stored bytes for sn. ok is false if sn was never recorded.
// payload may have length 0 (valid KCP PUSH); callers must not treat empty as "missing".
func (r *downstreamReplay) payloadForNREQ(sn uint32) (payload []byte, frg uint8, ok bool) {
	if r == nil {
		return nil, 0, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictStaleLocked(time.Now())
	seg, ok := r.bySN[sn]
	if !ok {
		return nil, 0, false
	}
	return seg.payload, seg.frg, true
}

// resolveWireSN maps a 16-bit-on-wire sequence number to the full uint32 key used in bySN.
// When the client is stuck at a low rcv_nxt but the server has advanced snd_nxt far ahead,
// expandSN16(snd_nxt, wire) picks the wrong lap (e.g. 65536 instead of 0); we scan laps in
// order and return the first sn present in the replay map with sn < sndNxt (when sndNxt > 0).

func (r *downstreamReplay) resolveWireSN(wire uint32, sndNxt uint32) (snFull uint32, ok bool) {
	if r == nil {
		return 0, false
	}
	w := wire & (kcpSNMod - 1)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictStaleLocked(time.Now())
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
