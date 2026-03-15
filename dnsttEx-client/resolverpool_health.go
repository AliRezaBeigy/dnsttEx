// Resolver pool health checking and probing. See resolverpool.go for types and NewResolverPool.

package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// healthLoop runs a ticker and probes each UDP endpoint; logs pool status after each round.
func (rp *ResolverPool) healthLoop(probeBuilder func() ([]byte, error), probeVerify func([]byte) bool) {
	interval := healthCheckInterval
	if testHookHealthCheckInterval != 0 {
		interval = testHookHealthCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-rp.done:
			return
		case <-ticker.C:
		}
		if probeBuilder == nil || probeVerify == nil {
			continue
		}
		var wg sync.WaitGroup
		for _, ep := range rp.endpoints {
			if ep.probeConn == nil {
				continue
			}
			wg.Add(1)
			ep := ep
			go func() {
				defer wg.Done()
				rp.probeEndpoint(ep, probeBuilder, probeVerify)
			}()
		}
		wg.Wait()
		rp.logPoolStatus()
	}
}

// logPoolStatus logs a one-line summary of pool health and current selection.
func (rp *ResolverPool) logPoolStatus() {
	snaps := make([]epSnap, len(rp.endpoints))
	for i, e := range rp.endpoints {
		h, r, rtt := e.snapshot()
		snaps[i] = epSnap{ep: e, healthy: h, ranked: r, rtt: rtt, bytes: e.bytesPassed.Load()}
	}
	var healthyNames, unhealthyNames []string
	var candidates []epSnap
	for _, s := range snaps {
		if s.healthy {
			healthyNames = append(healthyNames, s.ep.name)
			candidates = append(candidates, s)
		} else {
			unhealthyNames = append(unhealthyNames, s.ep.name)
		}
	}
	nHealthy := len(healthyNames)
	total := len(rp.endpoints)
	var selected string
	if nHealthy == 0 {
		selected = "none (all unhealthy, not sending to avoid network burst)"
	} else {
		switch rp.policy {
		case "least-ping":
			var unranked []epSnap
			for _, s := range candidates {
				if !s.ranked {
					unranked = append(unranked, s)
				}
			}
			if len(unranked) > 0 {
				selected = unranked[0].ep.name + " (unranked, round-robin)"
			} else {
				best := candidates[0]
				for _, s := range candidates[1:] {
					if s.rtt < best.rtt {
						best = s
					}
				}
				selected = fmt.Sprintf("%s (rtt=%v)", best.ep.name, best.rtt)
			}
		case "weighted-traffic":
			var totalB uint64
			for _, s := range candidates {
				totalB += s.bytes
			}
			if totalB == 0 {
				selected = candidates[0].ep.name + " (round-robin until traffic)"
			} else {
				selected = fmt.Sprintf("%s (weighted)", candidates[0].ep.name)
			}
		default:
			selected = fmt.Sprintf("%s (round-robin)", candidates[0].ep.name)
		}
	}
	respWindow := dataPathResponseWindow
	if testHookDataPathResponseWindow != 0 {
		respWindow = testHookDataPathResponseWindow
	}
	var coldNames []string
	for _, s := range candidates {
		last := s.ep.lastResponseTime.Load()
		sfStreak := s.ep.servfailStreak.Load()
		isCold := (last == 0 || time.Since(time.Unix(0, last)) >= respWindow) ||
			sfStreak >= servfailColdThreshold
		if isCold {
			label := s.ep.name
			if sfStreak >= servfailColdThreshold {
				label += fmt.Sprintf(" (SERVFAIL×%d)", sfStreak)
			}
			coldNames = append(coldNames, label)
		}
	}

	msg := fmt.Sprintf("resolver pool: %d/%d healthy", nHealthy, total)
	if nHealthy > 0 {
		msg += " — " + strings.Join(healthyNames, ", ")
	}
	if len(unhealthyNames) > 0 {
		msg += "; unhealthy: " + strings.Join(unhealthyNames, ", ")
	}
	if len(coldNames) > 0 {
		msg += fmt.Sprintf("; data-path cold (%d): %s", len(coldNames), strings.Join(coldNames, ", "))
	}
	msg += "; selected: " + selected
	log.Printf("resolverpool: %s", msg)
}

// probeEndpoint sends one probe on ep.probeConn and updates health/RTT accordingly.
func (rp *ResolverPool) probeEndpoint(ep *poolEndpoint, probeBuilder func() ([]byte, error), probeVerify func([]byte) bool) {
	msg, err := probeBuilder()
	if err != nil {
		return
	}

	timeout := healthCheckTimeout
	if testHookHealthCheckTimeout != 0 {
		timeout = testHookHealthCheckTimeout
	}
	deadline := time.Now().Add(timeout)
	start := time.Now()

	ep.probeConn.SetDeadline(deadline)
	_, err = ep.probeConn.WriteTo(msg, ep.addr)
	if err != nil {
		ep.probeConn.SetDeadline(time.Time{})
		if ep.recordFailure() {
			log.Printf("resolverpool: endpoint %s marked unhealthy (probe write: %v)", ep.name, err)
		}
		return
	}
	if dnsttDebug() {
		log.Printf("DNSTT_DEBUG: health PING query %s (hex):\n%s", ep.name, dnsttDebugHexDump(msg, 0))
	}

	buf := make([]byte, 4096)
	n, _, err := ep.probeConn.ReadFrom(buf)
	ep.probeConn.SetDeadline(time.Time{})
	if dnsttDebug() && err == nil {
		log.Printf("DNSTT_DEBUG: health PONG response %s (hex):\n%s", ep.name, dnsttDebugHexDump(buf[:n], 0))
	}
	if err != nil {
		if ep.recordFailure() {
			log.Printf("resolverpool: endpoint %s marked unhealthy (probe timeout: %v)", ep.name, err)
		}
		return
	}

	rtt := time.Since(start)
	if probeVerify(buf[:n]) {
		ep.setHealthy(rtt)
		log.Printf("resolverpool: endpoint %s healthy rtt=%v", ep.name, rtt)
	} else {
		if ep.recordFailure() {
			log.Printf("resolverpool: endpoint %s marked unhealthy (bad probe response)", ep.name)
		}
	}
}
