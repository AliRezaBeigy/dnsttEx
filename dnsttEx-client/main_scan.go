// Resolver scan and MTU discovery for dnstt-client.
// See main.go for package documentation and entry point.

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"
)

// shouldReportScanProgress returns true when a progress line should be logged
// (first, last, and roughly every 2% of total, interval capped).
func shouldReportScanProgress(done, total uint64) bool {
	if total == 0 {
		return false
	}
	if total == 1 || done == 1 || done == total {
		return true
	}
	interval := total / 50
	if interval < 1 {
		interval = 1
	}
	if interval > 100 {
		interval = 100
	}
	return done%interval == 0
}

// parseResolversFile parses a resolvers file and appends to specs.
// Format: one resolver per line, prefix doh:, dot:, or udp:. A bare IP or
// hostname with no prefix is treated as udp:host:53.
// Lines starting with # and blank lines are ignored.
func parseResolversFile(path string) ([]resolverSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var specs []resolverSpec
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		var typ, addr string
		if idx < 0 {
			typ = "udp"
			addr = line + ":53"
		} else {
			typ = strings.ToLower(line[:idx])
			addr = line[idx+1:]
		}
		switch typ {
		case "doh", "dot", "udp":
		default:
			return nil, fmt.Errorf("resolver file: unknown type %q in line %q", typ, line)
		}
		if typ == "doh" && !strings.HasPrefix(strings.ToLower(addr), "https://") {
			addr = "https://" + addr + "/dns-query"
		}
		specs = append(specs, resolverSpec{typ: typ, addr: addr})
	}
	return specs, scanner.Err()
}

// scanResolvers probes each endpoint and returns only those that get a valid
// server response within timeout. If checks > 1, each UDP endpoint is probed
// checks times and passes only if all checks succeed.
func scanResolvers(endpoints []*poolEndpoint, domain dns.Name, timeout time.Duration, checks int, retriesPerCheck int) []*poolEndpoint {
	if checks < 1 {
		checks = 1
	}
	if retriesPerCheck < 0 {
		retriesPerCheck = 0
	}
	probeID := turbotunnel.NewClientID()
	probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
	probeVerify := func(buf []byte) bool { return VerifyProbeResponse(buf, domain) }

	var mu sync.Mutex
	var passed []*poolEndpoint
	var wg sync.WaitGroup
	var scanDone atomic.Uint64
	totalEP := uint64(len(endpoints))

	for _, ep := range endpoints {
		ep := ep
		wg.Add(1)
		go func() {
			defer func() {
				n := scanDone.Add(1)
				if shouldReportScanProgress(n, totalEP) {
					mu.Lock()
					p := len(passed)
					mu.Unlock()
					log.Printf("Scan: progress %d/%d resolver(s) (%d passed so far)", n, totalEP, p)
				}
				wg.Done()
			}()

			if ep.probeConn == nil {
				log.Printf("Scan: %s (DoH/DoT) cannot probe; assumed OK", ep.name)
				mu.Lock()
				passed = append(passed, ep)
				mu.Unlock()
				return
			}

			for round := 0; round < checks; round++ {
				roundOK := false
				for attempt := 0; attempt <= retriesPerCheck; attempt++ {
					if attempt > 0 {
						log.Printf("Scan: %s — retry %d/%d (check %d/%d)", ep.name, attempt, retriesPerCheck, round+1, checks)
					}
					msg, err := probeBuilder()
					if err != nil {
						log.Printf("Scan: %s — PING build failed (check %d/%d): %v", ep.name, round+1, checks, err)
						return
					}
					ep.probeConn.SetDeadline(time.Now().Add(timeout))
					_, err = ep.probeConn.WriteTo(msg, ep.addr)
					if err != nil {
						ep.probeConn.SetDeadline(time.Time{})
						log.Printf("Scan: %s — PING send failed (check %d/%d, attempt %d): %v", ep.name, round+1, checks, attempt+1, err)
						if attempt == retriesPerCheck {
							return
						}
						continue
					}
					if dnsttDebug() {
						log.Printf("DNSTT_DEBUG: PING to %s (health probe, no requested payload size)", ep.name)
						log.Printf("DNSTT_DEBUG: PING query (hex):\n%s", dnsttDebugHexDump(msg, 0))
					}
					buf := make([]byte, 4096)
					n, _, err := ep.probeConn.ReadFrom(buf)
					ep.probeConn.SetDeadline(time.Time{})
					if err != nil {
						log.Printf("Scan: %s — no PONG (check %d/%d, attempt %d: %v)", ep.name, round+1, checks, attempt+1, err)
						if attempt == retriesPerCheck {
							return
						}
						continue
					}
					if dnsttDebug() {
						log.Printf("DNSTT_DEBUG: PONG response (hex):\n%s", dnsttDebugHexDump(buf[:n], 0))
					}
					if !probeVerify(buf[:n]) {
						log.Printf("Scan: %s → bad response (check %d/%d, attempt %d): %s", ep.name, round+1, checks, attempt+1, ExplainProbeResponseFailure(buf[:n], domain))
						if attempt == retriesPerCheck {
							return
						}
						continue
					}
					payloadLen := 0
					if resp, err := dns.MessageFromWireFormat(buf[:n]); err == nil {
						payload := dnsResponsePayload(&resp, domain)
						payloadLen = len(payload)
					}
					if checks == 1 && retriesPerCheck == 0 {
						log.Printf("Scan: %s → PONG received (%d bytes)", ep.name, payloadLen)
					} else {
						log.Printf("Scan: %s → PONG received (check %d/%d, attempt %d, %d bytes)", ep.name, round+1, checks, attempt+1, payloadLen)
					}
					if dnsttDebug() {
						log.Printf("DNSTT_DEBUG: PONG from %s payload %d bytes (health probe)", ep.name, payloadLen)
					}
					roundOK = true
					break
				}
				if !roundOK {
					return
				}
			}
			mu.Lock()
			passed = append(passed, ep)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return passed
}

// resolverLineForScanOutput formats a UDP resolver for writing to a resolvers file.
func resolverLineForScanOutput(udpAddr string) string {
	host, port, err := net.SplitHostPort(udpAddr)
	if err != nil {
		return "udp:" + udpAddr
	}
	if port == "53" {
		return host
	}
	return "udp:" + udpAddr
}

// scanUDPSingleConn runs PING/PONG against one UDP resolver using a single ephemeral
// socket, then closes it. Used for bulk scan to avoid Windows "buffer space / queue full".
func scanUDPSingleConn(udpAddrStr string, domain dns.Name, timeout time.Duration, checks, retriesPerCheck int, logName string) bool {
	if checks < 1 {
		checks = 1
	}
	if retriesPerCheck < 0 {
		retriesPerCheck = 0
	}
	udpAddr, err := net.ResolveUDPAddr("udp", udpAddrStr)
	if err != nil {
		log.Printf("Scan: %s — resolve: %v", logName, err)
		return false
	}
	lc := net.ListenConfig{Control: dialerControl}
	probeConn, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		log.Printf("Scan: %s — open socket: %v", logName, err)
		return false
	}
	defer probeConn.Close()

	probeID := turbotunnel.NewClientID()
	probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
	probeVerify := func(buf []byte) bool { return VerifyProbeResponse(buf, domain) }

	for round := 0; round < checks; round++ {
		roundOK := false
		for attempt := 0; attempt <= retriesPerCheck; attempt++ {
			if attempt > 0 {
				log.Printf("Scan: %s — retry %d/%d (check %d/%d)", logName, attempt, retriesPerCheck, round+1, checks)
			}
			msg, err := probeBuilder()
			if err != nil {
				log.Printf("Scan: %s — PING build failed (check %d/%d): %v", logName, round+1, checks, err)
				return false
			}
			probeConn.SetDeadline(time.Now().Add(timeout))
			_, err = probeConn.WriteTo(msg, udpAddr)
			if err != nil {
				probeConn.SetDeadline(time.Time{})
				log.Printf("Scan: %s — PING send failed (check %d/%d, attempt %d): %v", logName, round+1, checks, attempt+1, err)
				if attempt == retriesPerCheck {
					return false
				}
				continue
			}
			if dnsttDebug() {
				log.Printf("DNSTT_DEBUG: PING to %s (health probe, no requested payload size)", logName)
				log.Printf("DNSTT_DEBUG: PING query (hex):\n%s", dnsttDebugHexDump(msg, 0))
			}
			buf := make([]byte, 4096)
			n, _, err := probeConn.ReadFrom(buf)
			probeConn.SetDeadline(time.Time{})
			if err != nil {
				log.Printf("Scan: %s — no PONG (check %d/%d, attempt %d: %v)", logName, round+1, checks, attempt+1, err)
				if attempt == retriesPerCheck {
					return false
				}
				continue
			}
			if dnsttDebug() {
				log.Printf("DNSTT_DEBUG: PONG response (hex):\n%s", dnsttDebugHexDump(buf[:n], 0))
			}
			if !probeVerify(buf[:n]) {
				log.Printf("Scan: %s → bad response (check %d/%d, attempt %d): %s", logName, round+1, checks, attempt+1, ExplainProbeResponseFailure(buf[:n], domain))
				if attempt == retriesPerCheck {
					return false
				}
				continue
			}
			payloadLen := 0
			if resp, err := dns.MessageFromWireFormat(buf[:n]); err == nil {
				payload := dnsResponsePayload(&resp, domain)
				payloadLen = len(payload)
			}
			if checks == 1 && retriesPerCheck == 0 {
				log.Printf("Scan: %s → PONG received (%d bytes)", logName, payloadLen)
			} else {
				log.Printf("Scan: %s → PONG received (check %d/%d, attempt %d, %d bytes)", logName, round+1, checks, attempt+1, payloadLen)
			}
			if dnsttDebug() {
				log.Printf("DNSTT_DEBUG: PONG from %s payload %d bytes (health probe)", logName, payloadLen)
			}
			roundOK = true
			break
		}
		if !roundOK {
			return false
		}
	}
	return true
}

// mtuProbeResult is the result of one probe exchange in a concurrent round.
type mtuProbeResult int

const (
	mtuProbeResultTimeout mtuProbeResult = iota
	mtuProbeOK
	mtuProbePermanentFail
)

// serverMTUProbeRound sends attemptsBySize[size] probes for each size (unique QNAME per probe),
// then reads responses until timeout. It returns successful response count and permanent failures.
func serverMTUProbeRound(ep *poolEndpoint, domain dns.Name, probeID turbotunnel.ClientID, sizes []int, attemptsBySize map[int]int, timeout time.Duration) (map[int]int, map[int]bool) {
	expectedToSize := make(map[string]int)
	for _, size := range sizes {
		attempts := attemptsBySize[size]
		if attempts < 1 {
			attempts = 1
		}
		for i := 0; i < attempts; i++ {
			msg, err := BuildMTUProbeMessage(domain, probeID, size)
			if err != nil {
				continue
			}
			var expectedName string
			if q, e := dns.MessageFromWireFormat(msg); e == nil && len(q.Question) == 1 {
				expectedName = strings.ToLower(q.Question[0].Name.String())
			}
			if expectedName == "" {
				continue
			}
			if _, err := ep.probeConn.WriteTo(msg, ep.addr); err != nil {
				continue
			}
			expectedToSize[expectedName] = size
		}
	}
	if len(expectedToSize) == 0 {
		return map[int]int{}, map[int]bool{}
	}
	deadline := time.Now().Add(timeout)
	ep.probeConn.SetDeadline(deadline)
	buf := make([]byte, 8192)
	okCount := make(map[int]int)
	permanentFail := make(map[int]bool)
	for len(expectedToSize) > 0 {
		n, _, err := ep.probeConn.ReadFrom(buf)
		if err != nil {
			break
		}
		resp, parseErr := dns.MessageFromWireFormat(buf[:n])
		if parseErr != nil || len(resp.Question) != 1 {
			continue
		}
		expectedName := strings.ToLower(resp.Question[0].Name.String())
		size, ok := expectedToSize[expectedName]
		if !ok {
			continue
		}
		delete(expectedToSize, expectedName)
		if VerifyMTUProbeResponse(buf[:n], domain, size) {
			okCount[size]++
		} else {
			permanentFail[size] = true
		}
	}
	ep.probeConn.SetDeadline(time.Time{})
	return okCount, permanentFail
}

// clientMTUProbeRound is like serverMTUProbeRound but for client QNAME size probes.
func clientMTUProbeRound(ep *poolEndpoint, domain dns.Name, probeID turbotunnel.ClientID, sizes []int, attemptsBySize map[int]int, timeout time.Duration) (map[int]int, map[int]bool) {
	expectedToSize := make(map[string]int)
	for _, size := range sizes {
		attempts := attemptsBySize[size]
		if attempts < 1 {
			attempts = 1
		}
		for i := 0; i < attempts; i++ {
			msg, err := BuildProbeMessageWithRequestSize(domain, probeID, size)
			if err != nil {
				continue
			}
			var expectedName string
			if q, e := dns.MessageFromWireFormat(msg); e == nil && len(q.Question) == 1 {
				expectedName = strings.ToLower(q.Question[0].Name.String())
			}
			if expectedName == "" {
				continue
			}
			if _, err := ep.probeConn.WriteTo(msg, ep.addr); err != nil {
				continue
			}
			expectedToSize[expectedName] = size
		}
	}
	if len(expectedToSize) == 0 {
		return map[int]int{}, map[int]bool{}
	}
	deadline := time.Now().Add(timeout)
	ep.probeConn.SetDeadline(deadline)
	buf := make([]byte, 8192)
	okCount := make(map[int]int)
	permanentFail := make(map[int]bool)
	for len(expectedToSize) > 0 {
		n, _, err := ep.probeConn.ReadFrom(buf)
		if err != nil {
			break
		}
		resp, parseErr := dns.MessageFromWireFormat(buf[:n])
		if parseErr != nil || len(resp.Question) != 1 {
			continue
		}
		expectedName := strings.ToLower(resp.Question[0].Name.String())
		size, ok := expectedToSize[expectedName]
		if !ok {
			continue
		}
		delete(expectedToSize, expectedName)
		rcode := resp.Flags & 0x000f
		if rcode != dns.RcodeNoError {
			continue
		} else if VerifyProbeResponse(buf[:n], domain) {
			okCount[size]++
		} else {
			permanentFail[size] = true
		}
	}
	ep.probeConn.SetDeadline(time.Time{})
	return okCount, permanentFail
}

// mtuProbeOneExchange sends one probe and waits for a matching response until timeout.
// Returns (true, false) on success; (false, true) if the path definitively rejects this size;
// (false, false) on timeout, I/O error, or NXDOMAIN/DNS error (treated like timeout).
func mtuProbeOneExchange(ep *poolEndpoint, domain dns.Name, probeID turbotunnel.ClientID, size int, isServer bool, timeout time.Duration) (ok, permanentFail bool) {
	buf := make([]byte, 8192)

	for {
		var msg []byte
		var err error
		if isServer {
			msg, err = BuildMTUProbeMessage(domain, probeID, size)
		} else {
			msg, err = BuildProbeMessageWithRequestSize(domain, probeID, size)
		}
		if err != nil {
			return false, true
		}
		var expectedName string
		if q, e := dns.MessageFromWireFormat(msg); e == nil && len(q.Question) == 1 {
			expectedName = strings.ToLower(q.Question[0].Name.String())
		}
		if expectedName == "" {
			return false, true
		}
		if _, err := ep.probeConn.WriteTo(msg, ep.addr); err != nil {
			return false, false
		}
		ep.probeConn.SetDeadline(time.Now().Add(timeout))
		for {
			n, _, err := ep.probeConn.ReadFrom(buf)
			if err != nil {
				ep.probeConn.SetDeadline(time.Time{})
				return false, false
			}
			resp, parseErr := dns.MessageFromWireFormat(buf[:n])
			if parseErr != nil || len(resp.Question) != 1 {
				continue
			}
			if strings.ToLower(resp.Question[0].Name.String()) != expectedName {
				continue
			}
			ep.probeConn.SetDeadline(time.Time{})
			if isServer {
				if VerifyMTUProbeResponse(buf[:n], domain, size) {
					return true, false
				}
				return false, true
			}
			rcode := resp.Flags & 0x000f
			if rcode != dns.RcodeNoError {
				// NXDOMAIN or other DNS error: treat like timeout.
				return false, false
			}
			if VerifyProbeResponse(buf[:n], domain) {
				return true, false
			}
			return false, true
		}
	}
}

// mtuSizePassesProbes returns true only if this size succeeds mtuProbeSuccessesRequired times in a row;
// after each read timeout, up to mtuProbeAfterTimeoutRetries extra send/read cycles are tried per trial.
func mtuSizePassesProbes(ep *poolEndpoint, domain dns.Name, probeID turbotunnel.ClientID, size int, isServer bool, timeout time.Duration) bool {
	kind := "response"
	if !isServer {
		kind = "request"
	}
	for trial := 0; trial < mtuProbeSuccessesRequired; trial++ {
		gotOK := false
		for retry := 0; retry <= mtuProbeAfterTimeoutRetries; retry++ {
			ok, permanent := mtuProbeOneExchange(ep, domain, probeID, size, isServer, timeout)
			if ok {
				gotOK = true
				if dnsttDebug() {
					log.Printf("DNSTT_DEBUG: MTU probe %s: %s size %d OK (success %d/%d, timeout-retry %d)",
						ep.name, kind, size, trial+1, mtuProbeSuccessesRequired, retry)
				}
				break
			}
			if permanent {
				if dnsttDebug() {
					log.Printf("DNSTT_DEBUG: MTU probe %s: %s size %d rejected (verification failed)", ep.name, kind, size)
				}
				return false
			}
			if dnsttDebug() && retry < mtuProbeAfterTimeoutRetries {
				log.Printf("DNSTT_DEBUG: MTU probe %s: %s size %d timeout, retry %d/%d (trial %d/%d)",
					ep.name, kind, size, retry+1, mtuProbeAfterTimeoutRetries, trial+1, mtuProbeSuccessesRequired)
			}
		}
		if !gotOK {
			if dnsttDebug() {
				log.Printf("DNSTT_DEBUG: MTU probe %s: %s size %d failed trial %d/%d after timeouts",
					ep.name, kind, size, trial+1, mtuProbeSuccessesRequired)
			}
			return false
		}
	}
	return true
}

// mtuMaxConcurrentRounds limits how many rounds we run when a size keeps timing out.
const mtuMaxConcurrentRounds = 6

// discoverMTU finds max DNS response wire (server MTU) and max question QNAME length (client MTU)
// that work for this resolver. All candidate sizes are probed concurrently each round; each size
// must pass mtuProbeSuccessesRequired successful exchanges (across rounds). If clientMTUOverride > 0,
// client request size is not probed.
func discoverMTU(ep *poolEndpoint, domain dns.Name, timeout time.Duration, clientMTUOverride int) {
	if ep.probeConn == nil {
		return
	}
	probeID := turbotunnel.NewClientID()

	serverSizes := []int{256, 384, 512, 1024, 1232, 1452, 2048, 4096}
	clientSizes := []int{32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 255}

	if dnsttDebug() {
		log.Printf("DNSTT_DEBUG: MTU discovery %s: concurrent rounds, %d successes per size, max %d rounds",
			ep.name, mtuProbeSuccessesRequired, mtuMaxConcurrentRounds)
	}

	log.Printf("MTU discovery: %s — probing max DNS response payload (all sizes concurrently)…", ep.name)
	serverMTU := discoverMTUConcurrent(ep, domain, probeID, serverSizes, true, timeout, func(size int, okCount int) {
		log.Printf("MTU discovery: %s — response payload %d bytes: %d/%d OK", ep.name, size, okCount, mtuProbeSuccessesRequired)
	})
	if serverMTU > 0 {
		log.Printf("MTU discovery: %s — response payload %d bytes: OK", ep.name, serverMTU)
	}

	clientMTU := 0
	if clientMTUOverride > 0 {
		clientMTU = clientMTUOverride
		log.Printf("MTU discovery: %s — client query QNAME length fixed at %d bytes (-mtu)", ep.name, clientMTUOverride)
	} else {
		log.Printf("MTU discovery: %s — probing max query QNAME wire length (all sizes concurrently)…", ep.name)
		clientMTU = discoverMTUConcurrent(ep, domain, probeID, clientSizes, false, timeout, func(size int, okCount int) {
			log.Printf("MTU discovery: %s — QNAME ≥%d bytes: %d/%d OK", ep.name, size, okCount, mtuProbeSuccessesRequired)
		})
		if clientMTU > 0 {
			log.Printf("MTU discovery: %s — max QNAME length %d bytes: OK", ep.name, clientMTU)
		}
	}

	ep.setMaxSizes(serverMTU, clientMTU)
	log.Printf("MTU discovery: %s → max response wire %d bytes, max query QNAME %d bytes", ep.name, serverMTU, clientMTU)
}

// discoverMTUConcurrent runs concurrent probe rounds for the given sizes (descending order).
// It returns the largest size that achieved mtuProbeSuccessesRequired OKs. progress is called when
// a size gets another OK (okCount is the new count for that size).
func discoverMTUConcurrent(ep *poolEndpoint, domain dns.Name, probeID turbotunnel.ClientID, sizes []int, isServer bool, timeout time.Duration, progress func(size int, okCount int)) int {
	okCount := make(map[int]int)
	failed := make(map[int]bool)
	sizeIndex := make(map[int]int, len(sizes))
	noLargerProgressRounds := 0
	for _, s := range sizes {
		okCount[s] = 0
	}
	for i, s := range sizes {
		sizeIndex[s] = i
	}
	for round := 0; round < mtuMaxConcurrentRounds; round++ {
		var toProbe []int
		attemptsBySize := make(map[int]int)
		for _, s := range sizes {
			if !failed[s] && okCount[s] < mtuProbeSuccessesRequired {
				toProbe = append(toProbe, s)
				attemptsBySize[s] = mtuProbeSuccessesRequired - okCount[s]
			}
		}
		if len(toProbe) == 0 {
			break
		}
		var roundOK map[int]int
		var roundPermanentFail map[int]bool
		if isServer {
			roundOK, roundPermanentFail = serverMTUProbeRound(ep, domain, probeID, toProbe, attemptsBySize, timeout)
		} else {
			roundOK, roundPermanentFail = clientMTUProbeRound(ep, domain, probeID, toProbe, attemptsBySize, timeout)
		}
		roundProgress := make(map[int]int, len(roundOK))
		for size, n := range roundOK {
			roundProgress[size] = n
			for i := 0; i < n && okCount[size] < mtuProbeSuccessesRequired; i++ {
				okCount[size]++
				if progress != nil {
					progress(size, okCount[size])
				}
			}
		}
		for size := range roundPermanentFail {
			failed[size] = true
			// assumption: once one size is definitively rejected, all larger
			// sizes are rejected too for the same path.
			idx := sizeIndex[size]
			for j := idx + 1; j < len(sizes); j++ {
				failed[sizes[j]] = true
			}
		}
		// Aggressive fast path: once we have any fully accepted size, if the next
		// larger tier cannot complete all attempts in this round, prune it (and larger).
		// This treats timeout/loss at larger tiers as practical MTU failure to avoid
		// long tail waits.
		bestIdxNow := -1
		for i := len(sizes) - 1; i >= 0; i-- {
			if okCount[sizes[i]] >= mtuProbeSuccessesRequired {
				bestIdxNow = i
				break
			}
		}
		if bestIdxNow >= 0 {
			for i := bestIdxNow + 1; i < len(sizes); i++ {
				s := sizes[i]
				attempted := attemptsBySize[s]
				if attempted == 0 {
					continue
				}
				if roundOK[s] < attempted {
					failed[s] = true
					for j := i + 1; j < len(sizes); j++ {
						failed[sizes[j]] = true
					}
					break
				}
			}
		}
		// If we already have a best accepted size and all larger sizes are failed,
		// further rounds cannot improve the result.
		bestIdx := -1
		for i := len(sizes) - 1; i >= 0; i-- {
			if okCount[sizes[i]] >= mtuProbeSuccessesRequired {
				bestIdx = i
				break
			}
		}
		if bestIdx >= 0 {
			allLargerFailed := true
			largerProgress := false
			for i := bestIdx + 1; i < len(sizes); i++ {
				if !failed[sizes[i]] {
					allLargerFailed = false
				}
				if roundProgress[sizes[i]] > 0 {
					largerProgress = true
				}
			}
			if allLargerFailed {
				break
			}
			if largerProgress {
				noLargerProgressRounds = 0
			} else {
				noLargerProgressRounds++
				if noLargerProgressRounds >= 1 {
					break
				}
			}
		} else {
			noLargerProgressRounds = 0
		}
	}
	// Largest size with required OKs (sizes are in ascending order, so iterate backwards).
	for i := len(sizes) - 1; i >= 0; i-- {
		if okCount[sizes[i]] >= mtuProbeSuccessesRequired {
			return sizes[i]
		}
	}
	return 0
}

// RunScanCommand runs the standalone "scan" subcommand (args = os.Args[2:]).
// Returns exit code: 0 success, 1 usage/validation error, 2 flag parse error.
func RunScanCommand(scanArgs []string) int {
	scanFS := flag.NewFlagSet("scan", flag.ExitOnError)
	scanFS.SetOutput(os.Stderr)
	var scanDoh, scanDot, scanUdp stringSliceFlag
	var scanResolverFiles stringSliceFlag
	var scanUtls string
	var scanChecks, scanRetry int
	var scanDomain string
	scanFS.Var(&scanDoh, "doh", "DoH resolver URL (repeatable)")
	scanFS.Var(&scanDot, "dot", "DoT resolver address (repeatable)")
	scanFS.Var(&scanUdp, "udp", "UDP resolver host:port (repeatable)")
	scanFS.Var(&scanResolverFiles, "resolvers-file", "resolvers file (repeatable); same format as main client")
	scanFS.StringVar(&scanDomain, "domain", "", "tunnel DNS zone (required if only OUTPUT.txt is given as argument)")
	scanFS.StringVar(&scanUtls, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"uTLS distribution for DoH/DoT")
	scanFS.IntVar(&scanChecks, "scan-checks", 1, "PING/PONG rounds per resolver; all must succeed")
	scanFS.IntVar(&scanRetry, "scan-retry", 0, "extra attempts per check after failure (0 = no retry)")
	var scanParallel int
	scanFS.IntVar(&scanParallel, "scan-parallel", 64,
		"max concurrent UDP probes (lower if bind fails: buffer space / queue full on Windows)")
	scanFS.Usage = func() {
		fmt.Fprintf(scanFS.Output(), `Usage:
  %[1]s scan [flags] DOMAIN OUTPUT.txt
  %[1]s scan [flags] -domain DOMAIN OUTPUT.txt

  DOMAIN is your dnstt tunnel zone. Only resolvers that reach the dnstt server answer PONG.

  OUTPUT.txt: one passing UDP resolver per line (bare IP when port is 53).
  Large lists use -scan-parallel (default 64) so the OS is not flooded with sockets.

Examples:
  %[1]s scan -resolvers-file dns.txt -scan-checks 3 -scan-retry 2 t.example.com out.txt
  %[1]s scan -resolvers-file dns.txt -domain t.example.com -scan-checks 3 -scan-retry 2 out.txt

`, os.Args[0])
		scanFS.PrintDefaults()
	}
	if err := scanFS.Parse(scanArgs); err != nil {
		return 2
	}
	var domainStr, outPath string
	switch scanFS.NArg() {
	case 1:
		if scanDomain == "" {
			fmt.Fprintf(os.Stderr, "scan: give DOMAIN OUTPUT.txt, or -domain DOMAIN and OUTPUT.txt\n")
			scanFS.Usage()
			return 1
		}
		domainStr = scanDomain
		outPath = scanFS.Arg(0)
	case 2:
		domainStr = scanFS.Arg(0)
		outPath = scanFS.Arg(1)
	default:
		scanFS.Usage()
		return 1
	}
	domain, err := dns.ParseName(domainStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %q: %v\n", domainStr, err)
		return 1
	}

	var specs []resolverSpec
	for _, u := range scanDoh {
		specs = append(specs, resolverSpec{typ: "doh", addr: u})
	}
	for _, a := range scanDot {
		specs = append(specs, resolverSpec{typ: "dot", addr: a})
	}
	for _, a := range scanUdp {
		specs = append(specs, resolverSpec{typ: "udp", addr: a})
	}
	for _, path := range scanResolverFiles {
		fileSpecs, err := parseResolversFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading resolvers file %q: %v\n", path, err)
			return 1
		}
		specs = append(specs, fileSpecs...)
	}
	if len(specs) == 0 {
		fmt.Fprintf(os.Stderr, "scan: give at least one of -resolvers-file, -udp, -doh, -dot\n")
		return 1
	}
	if scanChecks < 1 {
		scanChecks = 1
	}
	if scanChecks > 20 {
		scanChecks = 20
	}
	if scanRetry < 0 {
		scanRetry = 0
	}
	if scanRetry > 10 {
		scanRetry = 10
	}
	if scanParallel < 1 {
		scanParallel = 1
	}
	if scanParallel > 512 {
		scanParallel = 512
	}

	if _, err := sampleUTLSDistribution(scanUtls); err != nil {
		fmt.Fprintf(os.Stderr, "scan: -utls: %v\n", err)
		return 1
	}

	log.SetFlags(log.LstdFlags | log.LUTC)

	var udpSpecs []resolverSpec
	var otherSpecs []resolverSpec
	seenAddr := make(map[string]bool)
	for _, spec := range specs {
		if spec.typ != "udp" {
			otherSpecs = append(otherSpecs, spec)
			continue
		}
		if seenAddr[spec.addr] {
			continue
		}
		seenAddr[spec.addr] = true
		udpSpecs = append(udpSpecs, spec)
	}

	timeout := 8 * time.Second
	var lines []string
	var linesMu sync.Mutex
	sem := make(chan struct{}, scanParallel)
	var wg sync.WaitGroup
	var doneUDP atomic.Uint64
	var passedUDP atomic.Uint64
	totalUDP := uint64(len(udpSpecs))

	log.Printf("Scan: %d UDP resolver(s), %d parallel, %d check(s) each, up to %d retries per check",
		len(udpSpecs), scanParallel, scanChecks, scanRetry)

	for _, spec := range udpSpecs {
		spec := spec
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			ok := scanUDPSingleConn(spec.addr, domain, timeout, scanChecks, scanRetry, "udp "+spec.addr)
			if ok {
				line := resolverLineForScanOutput(spec.addr)
				linesMu.Lock()
				lines = append(lines, line)
				linesMu.Unlock()
				passedUDP.Add(1)
			}
			n := doneUDP.Add(1)
			if shouldReportScanProgress(n, totalUDP) {
				log.Printf("Scan: progress %d/%d UDP (%d passed)", n, totalUDP, passedUDP.Load())
			}
		}()
	}
	wg.Wait()

	if len(otherSpecs) > 0 {
		log.Printf("Scan: ignoring %d DoH/DoT resolver(s) (output file is UDP PONG only)", len(otherSpecs))
	}

	out, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: create output %q: %v\n", outPath, err)
		return 1
	}
	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
	if err := out.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "scan: close output: %v\n", err)
		return 1
	}

	log.Printf("Scan: wrote %d resolver(s) with PONG to %q (%d/%d UDP tried)", len(lines), outPath, len(lines), len(udpSpecs))
	return 0
}
