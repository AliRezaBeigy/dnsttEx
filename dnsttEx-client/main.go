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
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"dnsttEx/dns"
	"dnsttEx/noise"

	utls "github.com/refraction-networking/utls"
)

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

func main() {
	// If no args, try SS_PLUGIN_OPTIONS for Shadowsocks plugin compatibility.
	applyShadowsocksPluginOptsIfNeeded()

	// Standalone scan: test resolvers with PING/PONG and write passing UDP lines to a file.
	if len(os.Args) >= 2 && os.Args[1] == "scan" {
		os.Exit(RunScanCommand(os.Args[2:]))
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
	var tunnelMode string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-udp ADDR] (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) [-tunnel tcp|socks] DOMAIN LOCALADDR

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -doh url1 -doh url2 -resolver-policy least-ping -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -resolvers-file resolvers.txt -scan -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -udp 8.8.8.8:53 -pubkey-file server.pub -tunnel socks t.example.com 127.0.0.1:1080

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
	flag.StringVar(&tunnelMode, "tunnel", "socks", "tcp: LOCALADDR is plain TCP forward; socks: LOCALADDR is SOCKS5 (server needs -tunnel socks)")
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

	switch tunnelMode {
	case "tcp", "socks":
	default:
		fmt.Fprintf(os.Stderr, "-tunnel must be tcp or socks, not %q\n", tunnelMode)
		os.Exit(1)
	}

	// Validate policy.
	switch resolverPolicy {
	case "round-robin", "least-ping", "weighted-traffic":
	default:
		fmt.Fprintf(os.Stderr, "invalid -resolver-policy %q; must be round-robin, least-ping, or weighted-traffic\n", resolverPolicy)
		os.Exit(1)
	}

	err = runTunnel(domain, localAddr, pubkey, utlsClientHelloID, specs, resolverPolicy, doScan, scanChecks, clientMTUFlag, sendParallel, tunnelMode)
	if err != nil {
		log.Fatal(err)
	}
}
