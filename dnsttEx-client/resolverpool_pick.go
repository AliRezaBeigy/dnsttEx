// Resolver pool endpoint selection (getCandidates, pickNEndpoints, pickEndpoint).
// See resolverpool.go for types and NewResolverPool.

package main

import (
	"math/rand"
	"sync/atomic"
	"time"
)

// getCandidates returns healthy endpoints, filtered by data-path responsiveness.
// Caller must not modify the returned slice.
func (rp *ResolverPool) getCandidates() []epSnap {
	snaps := make([]epSnap, len(rp.endpoints))
	for i, e := range rp.endpoints {
		h, r, rtt := e.snapshot()
		snaps[i] = epSnap{ep: e, healthy: h, ranked: r, rtt: rtt, bytes: e.bytesPassed.Load()}
	}
	candidates := snaps[:0:0]
	for _, s := range snaps {
		if s.healthy {
			candidates = append(candidates, s)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	respWindow := dataPathResponseWindow
	if testHookDataPathResponseWindow != 0 {
		respWindow = testHookDataPathResponseWindow
	}
	var responsive, cold []epSnap
	for _, s := range candidates {
		last := s.ep.lastResponseTime.Load()
		sfStreak := s.ep.servfailStreak.Load()
		isCold := (last == 0 || time.Since(time.Unix(0, last)) >= respWindow) ||
			sfStreak >= servfailColdThreshold
		if isCold {
			cold = append(cold, s)
		} else {
			responsive = append(responsive, s)
		}
	}
	if len(responsive) > 0 && len(cold) > 0 {
		queryNum := atomic.AddUint64(&rp.reprobeIdx, 1)
		if queryNum%uint64(reprobeEvery) == 0 {
			coldIdx := (queryNum / uint64(reprobeEvery)) % uint64(len(cold))
			return []epSnap{cold[coldIdx]}
		}
		return responsive
	}
	return candidates
}

// pickNEndpoints selects up to n endpoints for parallel send.
func (rp *ResolverPool) pickNEndpoints(n int) []*poolEndpoint {
	candidates := rp.getCandidates()
	if len(candidates) == 0 {
		return nil
	}
	if n <= 0 {
		n = 1
	}
	k := n
	if k > len(candidates) {
		k = len(candidates)
	}
	idx := atomic.AddUint64(&rp.rrIndex, uint64(k)) - uint64(k)
	out := make([]*poolEndpoint, k)
	for i := 0; i < k; i++ {
		out[i] = candidates[(int(idx)+i)%len(candidates)].ep
	}
	return out
}

// pickEndpoint selects one endpoint by the configured policy.
func (rp *ResolverPool) pickEndpoint() *poolEndpoint {
	candidates := rp.getCandidates()
	if len(candidates) == 0 {
		return nil
	}

	switch rp.policy {
	case "least-ping":
		var unranked []epSnap
		for _, s := range candidates {
			if !s.ranked {
				unranked = append(unranked, s)
			}
		}
		if len(unranked) > 0 {
			idx := atomic.AddUint64(&rp.rrIndex, 1) - 1
			return unranked[idx%uint64(len(unranked))].ep
		}
		best := candidates[0]
		for _, s := range candidates[1:] {
			if s.rtt < best.rtt {
				best = s
			}
		}
		return best.ep

	case "weighted-traffic":
		var total uint64
		for _, s := range candidates {
			total += s.bytes
		}
		if total == 0 {
			break
		}
		r := uint64(rand.Int63n(int64(total)))
		var cum uint64
		for _, s := range candidates {
			cum += s.bytes
			if r < cum {
				return s.ep
			}
		}
		return candidates[len(candidates)-1].ep
	}

	idx := atomic.AddUint64(&rp.rrIndex, 1) - 1
	return candidates[idx%uint64(len(candidates))].ep
}
