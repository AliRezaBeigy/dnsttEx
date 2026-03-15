// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client [-doh URL|-dot ADDR|-udp ADDR] (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN LOCALADDR
//
// Examples:
//
//	dnstt-client -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-udp resolver.example:53
//
// Flags may be repeated to specify multiple resolvers:
//
//	-doh url1 -doh url2 -dot addr1 -udp addr2
//
// A resolver file may also be given:
//
//	-resolvers-file /path/to/resolvers.txt
//
// Resolver scan (write resolvers that return PONG to a file):
//
//	dnstt-client scan -resolvers-file dns.txt -scan-checks 3 -scan-retry 2 t.example.com output.txt
//	dnstt-client scan -resolvers-file dns.txt -domain t.example.com -scan-checks 3 -scan-retry 2 output.txt
//
// File format: one resolver per line, prefix doh:, dot:, or udp:.
// Lines starting with # or blank lines are ignored.
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// LOCALADDR is the TCP address that will listen for connections and forward
// them over the tunnel.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dnsttEx/dns"
	"dnsttEx/noise"
	"dnsttEx/turbotunnel"

	utls "github.com/refraction-networking/utls"
)

// smux streams will be closed after this much time without receiving data.
const (
	idleTimeout = 2 * time.Minute
	// mtuProbeNXDOMAINRetries: when request-size MTU probe gets NXDOMAIN, retry this many times before giving up.
	mtuProbeNXDOMAINRetries = 3
	// mtuProbeErrorRetries: when an MTU probe times out or hits a transient read/write
	// error, retry it this many times before treating that size as failed.
	mtuProbeErrorRetries = 2
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

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

var dialerControl func(network, address string, c syscall.RawConn) error = nil

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

func main() {
	// If no command-line arguments are given, try to read options from
	// environment variables, for compatibility with shadowsocks plugins.
	// ss-local -s 0.0.0.1 -p 1 -l 1080 -k password --plugin dnstt-client --plugin-opts 'doh=https://doh.example/dns-query;domain=<domain>;pubkey=<pubkey>'
	if len(os.Args) == 1 {
		pluginOpts := os.Getenv("SS_PLUGIN_OPTIONS")
		if pluginOpts != "" {
			var dohURLs, dotAddrs, udpAddrs []string
			var resolverFiles []string
			var pubkey, domainStr, policy string

			options := strings.Split(pluginOpts, ";")
			for _, opt := range options {
				parts := strings.SplitN(opt, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				switch key {
				case "doh":
					if !strings.HasPrefix(strings.ToLower(value), "https://") {
						value = "https://" + value + "/dns-query"
					}
					dohURLs = append(dohURLs, value)
				case "dot":
					dotAddrs = append(dotAddrs, value)
				case "udp":
					udpAddrs = append(udpAddrs, value)
				case "resolvers-file":
					resolverFiles = append(resolverFiles, value)
				case "resolver-policy":
					policy = value
				case "pubkey":
					pubkey = value
				case "domain":
					domainStr = value
				case "__android_vpn":
					dialerControl = dialerControlVpn
				}
			}

			localHost := os.Getenv("SS_LOCAL_HOST")
			localPort := os.Getenv("SS_LOCAL_PORT")

			if len(dohURLs)+len(dotAddrs)+len(udpAddrs)+len(resolverFiles) == 0 {
				// Fallback: check remote host/port.
				remoteHost := os.Getenv("SS_REMOTE_HOST")
				remotePort := os.Getenv("SS_REMOTE_PORT")
				if remoteHost == "" || remotePort == "" {
					fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain one of: doh, dot, udp, or resolvers-file\n")
					os.Exit(1)
				}
				udpAddrs = append(udpAddrs, net.JoinHostPort(remoteHost, remotePort))
			}
			if pubkey == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain pubkey\n")
				os.Exit(1)
			}
			if domainStr == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain domain\n")
				os.Exit(1)
			}
			if localHost == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_LOCAL_HOST environment variable not set\n")
				os.Exit(1)
			}
			if localPort == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_LOCAL_PORT environment variable not set\n")
				os.Exit(1)
			}

			// Reconstruct os.Args so the existing flag-parsing logic can be used.
			args := []string{os.Args[0]}
			for _, u := range dohURLs {
				args = append(args, "-doh", u)
			}
			for _, a := range dotAddrs {
				args = append(args, "-dot", a)
			}
			for _, a := range udpAddrs {
				args = append(args, "-udp", a)
			}
			for _, f := range resolverFiles {
				args = append(args, "-resolvers-file", f)
			}
			if policy != "" {
				args = append(args, "-resolver-policy", policy)
			}
			args = append(args, "-pubkey", pubkey, domainStr, net.JoinHostPort(localHost, localPort))
			os.Args = args
		}
	}

	// Standalone scan: test resolvers with PING/PONG and write passing UDP lines to a file.
	// Usage: dnstt-client scan [-resolvers-file FILE]... [-udp ADDR]... [-scan-checks N] [-scan-retry R] DOMAIN OUTPUT.txt
	if len(os.Args) >= 2 && os.Args[1] == "scan" {
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
		if err := scanFS.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}
		var domainStr, outPath string
		switch scanFS.NArg() {
		case 1:
			if scanDomain == "" {
				fmt.Fprintf(os.Stderr, "scan: give DOMAIN OUTPUT.txt, or -domain DOMAIN and OUTPUT.txt\n")
				scanFS.Usage()
				os.Exit(1)
			}
			domainStr = scanDomain
			outPath = scanFS.Arg(0)
		case 2:
			domainStr = scanFS.Arg(0)
			outPath = scanFS.Arg(1)
		default:
			scanFS.Usage()
			os.Exit(1)
		}
		domain, err := dns.ParseName(domainStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid domain %q: %v\n", domainStr, err)
			os.Exit(1)
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
				os.Exit(1)
			}
			specs = append(specs, fileSpecs...)
		}
		if len(specs) == 0 {
			fmt.Fprintf(os.Stderr, "scan: give at least one of -resolvers-file, -udp, -doh, -dot\n")
			os.Exit(1)
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
			os.Exit(1)
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
			os.Exit(1)
		}
		for _, line := range lines {
			fmt.Fprintln(out, line)
		}
		if err := out.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "scan: close output: %v\n", err)
			os.Exit(1)
		}

		log.Printf("Scan: wrote %d resolver(s) with PONG to %q (%d/%d UDP tried)", len(lines), outPath, len(lines), len(udpSpecs))
		os.Exit(0)
	}

	var dohURLs stringSliceFlag
	var dotAddrs stringSliceFlag
	var udpAddrs stringSliceFlag
	var resolverFiles stringSliceFlag
	var pubkeyFilename string
	var pubkeyString string
	var utlsDistribution string
	var resolverPolicy string
	var doScan bool
	var scanChecks int
	var clientMTUFlag int

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-udp ADDR] (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN LOCALADDR

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -doh url1 -doh url2 -resolver-policy least-ping -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -resolvers-file resolvers.txt -scan -pubkey-file server.pub t.example.com 127.0.0.1:7000

`, os.Args[0])
		flag.PrintDefaults()
		labels := make([]string, 0, len(utlsClientHelloIDMap))
		labels = append(labels, "none")
		for _, entry := range utlsClientHelloIDMap {
			labels = append(labels, entry.Label)
		}
		fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			fmt.Fprintf(&line, "  %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				fmt.Fprintf(&line, " %s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}
	flag.Var(&dohURLs, "doh", "URL of DoH resolver (may be repeated)")
	flag.Var(&dotAddrs, "dot", "address of DoT resolver (may be repeated)")
	flag.Var(&udpAddrs, "udp", "address of UDP DNS resolver (may be repeated)")
	flag.Var(&resolverFiles, "resolvers-file", "file with one resolver per line (doh:URL, dot:host:port, udp:host:port, or bare IP/host as udp:53); may be repeated")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"choose TLS fingerprint from weighted distribution")
	flag.StringVar(&resolverPolicy, "resolver-policy", "round-robin",
		"resolver selection policy when multiple resolvers are used: round-robin, least-ping, weighted-traffic")
	var sendParallel int
	flag.IntVar(&sendParallel, "send-parallel", 1,
		"number of resolvers to use per send (same packet sent to each); at least one success counts as success (default 1)")
	flag.BoolVar(&doScan, "scan", false,
		"pre-start scan: test each resolver and keep only those that receive a valid server response")
	flag.IntVar(&scanChecks, "scan-checks", 1,
		"when -scan is used, run this many PING checks per resolver; a resolver passes only if all checks succeed (default 1, use higher for stricter scan)")
	flag.IntVar(&clientMTUFlag, "mtu", 0,
		"max question QNAME wire length in bytes (what many DPI systems limit—not full UDP size). 0 = discover per resolver. Response size is still discovered.")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		var err error
		pubkey, err = readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
	} else if pubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubkey format error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(pubkey) == 0 {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Build the merged resolver list from flags and files.
	var specs []resolverSpec
	for _, u := range dohURLs {
		specs = append(specs, resolverSpec{typ: "doh", addr: u})
	}
	for _, a := range dotAddrs {
		specs = append(specs, resolverSpec{typ: "dot", addr: a})
	}
	for _, a := range udpAddrs {
		specs = append(specs, resolverSpec{typ: "udp", addr: a})
	}
	for _, path := range resolverFiles {
		fileSpecs, err := parseResolversFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading resolvers file %q: %v\n", path, err)
			os.Exit(1)
		}
		specs = append(specs, fileSpecs...)
	}

	if len(specs) == 0 {
		fmt.Fprintf(os.Stderr, "one of -doh, -dot, -udp, or -resolvers-file is required\n")
		os.Exit(1)
	}

	// Validate policy.
	switch resolverPolicy {
	case "round-robin", "least-ping", "weighted-traffic":
	default:
		fmt.Fprintf(os.Stderr, "invalid -resolver-policy %q; must be round-robin, least-ping, or weighted-traffic\n", resolverPolicy)
		os.Exit(1)
	}

	// Build endpoints.
	endpoints := make([]*poolEndpoint, 0, len(specs))
	for _, spec := range specs {
		ep, _, err := buildEndpointFromSpec(spec, utlsClientHelloID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error initializing resolver %s %s: %v\n", spec.typ, spec.addr, err)
			os.Exit(1)
		}
		endpoints = append(endpoints, ep)
	}

	// Pre-start scan: filter to only resolvers that get a valid server response.
	if doScan {
		if scanChecks < 1 {
			scanChecks = 1
		}
		if scanChecks > 20 {
			scanChecks = 20
		}
		log.Printf("Scan: sending PING to %d resolver(s) (%d check(s) each)", len(endpoints), scanChecks)
		passed := scanResolvers(endpoints, domain, 8*time.Second, scanChecks, 0)
		// Close endpoints that didn't pass.
		passedSet := make(map[*poolEndpoint]bool, len(passed))
		for _, ep := range passed {
			passedSet[ep] = true
		}
		for _, ep := range endpoints {
			if !passedSet[ep] {
				ep.conn.Close()
				if ep.probeConn != nil {
					ep.probeConn.Close()
				}
			}
		}
		if len(passed) == 0 {
			fmt.Fprintf(os.Stderr, "no resolvers passed -scan; check your resolver list and that the server is reachable\n")
			os.Exit(1)
		}
		log.Printf("Scan: %d/%d resolver(s) responded with PONG", len(passed), len(endpoints))
		endpoints = passed
	}

	// MTU discovery: always probe server (response) size; probe client (request) size only when -mtu not set.
	mtuTimeout := mtuProbeTimeout()
	{
		var wg sync.WaitGroup
		for _, ep := range endpoints {
			wg.Add(1)
			go func(ep *poolEndpoint) {
				defer wg.Done()
				discoverMTU(ep, domain, mtuTimeout, clientMTUFlag)
			}(ep)
		}
		wg.Wait()
	}
	if clientMTUFlag > 0 {
		log.Printf("Using client max query QNAME length %d bytes (-mtu)", clientMTUFlag)
	}

	// Drop UDP resolvers that never succeeded a server (response) MTU probe — they
	// cannot carry tunneled answers. DoH/DoT skip discoverMTU (probeConn nil); keep those.
	{
		var kept []*poolEndpoint
		for _, ep := range endpoints {
			if ep.probeConn == nil {
				kept = append(kept, ep)
				continue
			}
			maxResp, _ := ep.getMaxSizes()
			if maxResp > 0 {
				kept = append(kept, ep)
				continue
			}
			log.Printf("MTU: dropping %s (no response-size probe success; unusable for tunnel)", ep.name)
			ep.conn.Close()
			if ep.probeConn != nil {
				ep.probeConn.Close()
			}
		}
		if dropped := len(endpoints) - len(kept); dropped > 0 {
			log.Printf("MTU: removed %d/%d resolver(s) with max response wire 0", dropped, len(endpoints))
		}
		endpoints = kept
		if len(endpoints) == 0 {
			fmt.Fprintf(os.Stderr, "no resolvers left after MTU discovery (every UDP resolver failed response-size probes)\n")
			os.Exit(1)
		}
	}

	// Build the transport pconn.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	var effectiveMaxResponse, effectiveMaxRequest int

	if len(endpoints) == 1 {
		// Single resolver: keep current behavior. Close probeConn so the probe
		// socket is not leaked (pool is not used, so it would never be closed).
		effectiveMaxResponse, effectiveMaxRequest = endpoints[0].getMaxSizes()
		if effectiveMaxResponse <= 0 {
			effectiveMaxResponse = 4096
		}
		if endpoints[0].probeConn != nil {
			endpoints[0].probeConn.Close()
			endpoints[0].probeConn = nil
		}
		pconn = endpoints[0].conn
		remoteAddr = endpoints[0].addr
	} else {
		// Multiple resolvers: wrap in ResolverPool.
		if sendParallel < 1 {
			sendParallel = 1
		}
		probeID := turbotunnel.NewClientID()
		probeBuilder := func() ([]byte, error) { return BuildProbeMessage(domain, probeID) }
		probeVerify := func(buf []byte) bool { return VerifyProbeResponse(buf, domain) }
		pool := NewResolverPool(endpoints, resolverPolicy, sendParallel, probeBuilder, probeVerify)
		pconn = pool
		remoteAddr = turbotunnel.DummyAddr{}
		effectiveMaxResponse = pool.MinMaxResponseSize(4096)
		effectiveMaxRequest = pool.MinMaxRequestSize(0)
		log.Printf("Using %d resolver(s), policy: %q, send-parallel: %d", len(endpoints), resolverPolicy, sendParallel)
	}
	if clientMTUFlag > 0 && (effectiveMaxRequest <= 0 || clientMTUFlag < effectiveMaxRequest) {
		effectiveMaxRequest = clientMTUFlag
	}

	pconn = NewDNSPacketConn(pconn, remoteAddr, domain, effectiveMaxResponse, effectiveMaxRequest)
	err = run(pubkey, domain, localAddr, remoteAddr, pconn)
	if err != nil {
		log.Fatal(err)
	}
}
