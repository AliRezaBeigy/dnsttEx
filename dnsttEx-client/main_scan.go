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

	for _, ep := range endpoints {
		ep := ep
		wg.Add(1)
		go func() {
			defer wg.Done()

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
					if checks == 1 && retriesPerCheck == 0 {
						log.Printf("Scan: %s ← PING sent", ep.name)
					} else {
						log.Printf("Scan: %s ← PING sent (check %d/%d, attempt %d)", ep.name, round+1, checks, attempt+1)
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
			if checks == 1 && retriesPerCheck == 0 {
				log.Printf("Scan: %s ← PING sent", logName)
			} else {
				log.Printf("Scan: %s ← PING sent (check %d/%d, attempt %d)", logName, round+1, checks, attempt+1)
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

// mtuProbe represents a single MTU probe (server response size or client request size).
type mtuProbe struct {
	msg          []byte
	expectedName string
	size         int
	isServer     bool
	succeeded    bool
	skipRetry    bool
}

func (p *mtuProbe) done() bool { return p.succeeded || p.skipRetry }

// discoverMTU finds max DNS response wire (server MTU) and max question QNAME length (client MTU)
// that work for this resolver. If clientMTUOverride > 0, client request size is not probed.
func discoverMTU(ep *poolEndpoint, domain dns.Name, timeout time.Duration, clientMTUOverride int) {
	if ep.probeConn == nil {
		return
	}
	probeID := turbotunnel.NewClientID()

	serverSizes := []int{256, 384, 512, 1024, 1232, 1452, 2048, 4096}
	clientSizes := []int{32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 255}
	if clientMTUOverride > 0 {
		clientSizes = nil
	}

	probes := make([]*mtuProbe, 0, len(serverSizes)+len(clientSizes))
	// Key by lowercase so we match responses when relay applies 0x20 QNAME randomization.
	nameToProbe := make(map[string]*mtuProbe, len(serverSizes)+len(clientSizes))

	for _, size := range serverSizes {
		msg, err := BuildMTUProbeMessage(domain, probeID, size)
		if err != nil {
			continue
		}
		var name string
		if q, e := dns.MessageFromWireFormat(msg); e == nil && len(q.Question) == 1 {
			name = q.Question[0].Name.String()
		}
		p := &mtuProbe{msg: msg, expectedName: name, size: size, isServer: true}
		probes = append(probes, p)
		if name != "" {
			nameToProbe[strings.ToLower(name)] = p
		}
	}
	for _, size := range clientSizes {
		msg, err := BuildProbeMessageWithRequestSize(domain, probeID, size)
		if err != nil {
			continue
		}
		var name string
		if q, e := dns.MessageFromWireFormat(msg); e == nil && len(q.Question) == 1 {
			name = q.Question[0].Name.String()
		}
		p := &mtuProbe{msg: msg, expectedName: name, size: size, isServer: false}
		probes = append(probes, p)
		if name != "" {
			nameToProbe[strings.ToLower(name)] = p
		}
	}

	if dnsttDebug() {
		log.Printf("DNSTT_DEBUG: MTU discovery %s: %d probes (%d server + %d client), sending concurrently",
			ep.name, len(probes), len(serverSizes), len(clientSizes))
	}

	const maxRounds = 2
	for round := 0; round < maxRounds; round++ {
		pending := 0
		for _, p := range probes {
			if !p.done() {
				pending++
			}
		}
		if pending == 0 {
			break
		}
		if dnsttDebug() && round > 0 {
			log.Printf("DNSTT_DEBUG: MTU discovery %s: round %d, retrying %d unanswered probes",
				ep.name, round+1, pending)
		}

		sent := 0
		for _, p := range probes {
			if p.done() {
				continue
			}
			if _, err := ep.probeConn.WriteTo(p.msg, ep.addr); err != nil {
				if dnsttDebug() {
					kind := "response"
					if !p.isServer {
						kind = "request"
					}
					log.Printf("DNSTT_DEBUG: MTU probe %s: round %d write error (%s size %d): %v",
						ep.name, round+1, kind, p.size, err)
				}
				continue
			}
			sent++
		}

		deadline := time.Now().Add(timeout)
		ep.probeConn.SetDeadline(deadline)
		received := 0
		for {
			buf := make([]byte, 4096)
			n, _, err := ep.probeConn.ReadFrom(buf)
			if err != nil {
				break
			}
			received++
			resp, parseErr := dns.MessageFromWireFormat(buf[:n])
			if parseErr != nil || len(resp.Question) != 1 {
				if received >= sent {
					break
				}
				continue
			}
			p, found := nameToProbe[strings.ToLower(resp.Question[0].Name.String())]
			if !found || p.done() {
				if received >= sent {
					break
				}
				continue
			}

			ok := false
			if p.isServer {
				ok = VerifyMTUProbeResponse(buf[:n], domain, p.size)
			} else {
				ok = VerifyProbeResponse(buf[:n], domain)
			}
			if ok {
				p.succeeded = true
			} else {
				p.skipRetry = true
			}
			if dnsttDebug() {
				kind := "response"
				if !p.isServer {
					kind = "request"
				}
				if ok {
					log.Printf("DNSTT_DEBUG: MTU probe %s: %s size %d OK (round %d)",
						ep.name, kind, p.size, round+1)
				} else {
					log.Printf("DNSTT_DEBUG: MTU probe %s: %s size %d verification failed (round %d)",
						ep.name, kind, p.size, round+1)
				}
			}

			allDone := true
			for _, p := range probes {
				if !p.done() {
					allDone = false
					break
				}
			}
			if allDone || received >= sent {
				break
			}
		}
		ep.probeConn.SetDeadline(time.Time{})

		maxServerOK, maxClientOK := 0, 0
		for _, p := range probes {
			if !p.succeeded {
				continue
			}
			if p.isServer && p.size > maxServerOK {
				maxServerOK = p.size
			}
			if !p.isServer && p.size > maxClientOK {
				maxClientOK = p.size
			}
		}
		for _, p := range probes {
			if p.done() {
				continue
			}
			if p.isServer && maxServerOK > 0 && p.size > maxServerOK {
				p.skipRetry = true
			}
			if !p.isServer && maxClientOK > 0 && p.size > maxClientOK {
				p.skipRetry = true
			}
		}
	}

	serverMTU := 0
	clientMTU := 0
	for _, p := range probes {
		if !p.succeeded {
			continue
		}
		if p.isServer && p.size > serverMTU {
			serverMTU = p.size
		}
		if !p.isServer && p.size > clientMTU {
			clientMTU = p.size
		}
	}
	if clientMTUOverride > 0 {
		clientMTU = clientMTUOverride
	}

	ep.setMaxSizes(serverMTU, clientMTU)
	log.Printf("MTU discovery: %s → max response wire %d bytes, max query QNAME %d bytes", ep.name, serverMTU, clientMTU)
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

	log.Printf("Scan: %d UDP resolver(s), %d parallel, %d check(s) each, up to %d retries per check",
		len(udpSpecs), scanParallel, scanChecks, scanRetry)

	for _, spec := range udpSpecs {
		spec := spec
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			if scanUDPSingleConn(spec.addr, domain, timeout, scanChecks, scanRetry, "udp "+spec.addr) {
				line := resolverLineForScanOutput(spec.addr)
				linesMu.Lock()
				lines = append(lines, line)
				linesMu.Unlock()
			}
			n := doneUDP.Add(1)
			if n%500 == 0 || n == uint64(len(udpSpecs)) {
				log.Printf("Scan: progress %d/%d UDP", n, len(udpSpecs))
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
