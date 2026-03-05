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
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"dnsttEx/dns"
	"dnsttEx/noise"
	"dnsttEx/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

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

// sessionManager manages the KCP connection, Noise channel, and smux session,
// and can recreate them if they become closed.
type sessionManager struct {
	pubkey     []byte
	domain     dns.Name
	remoteAddr net.Addr
	pconn      net.PacketConn
	mtu        int

	mu   sync.RWMutex
	conn *kcp.UDPSession
	rw   io.ReadWriteCloser
	sess *smux.Session
	conv uint32
}

// newSessionManager creates a new session manager.
func newSessionManager(pubkey []byte, domain dns.Name, remoteAddr net.Addr, pconn net.PacketConn, mtu int) *sessionManager {
	return &sessionManager{
		pubkey:     pubkey,
		domain:     domain,
		remoteAddr: remoteAddr,
		pconn:      pconn,
		mtu:        mtu,
	}
}

// closeSessionLocked closes the current session if it exists.
// Caller must hold sm.mu write lock.
func (sm *sessionManager) closeSessionLocked() {
	if sm.sess != nil {
		sm.sess.Close()
		sm.sess = nil
	}
	if sm.rw != nil {
		sm.rw.Close()
		sm.rw = nil
	}
	if sm.conn != nil {
		conv := sm.conv
		log.Printf("end session %08x", conv)
		sm.conn.Close()
		sm.conn = nil
	}
	sm.conv = 0
}

// createSessionUnlocked creates a new KCP connection, Noise channel, and smux
// session. It does not touch sm.mu and must be called without holding it.
func (sm *sessionManager) createSessionUnlocked() (*kcp.UDPSession, io.ReadWriteCloser, *smux.Session, uint32, error) {
	conn, err := kcp.NewConn2(sm.remoteAddr, nil, 0, 0, sm.pconn)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("opening KCP conn: %v", err)
	}
	conv := conn.GetConv()
	log.Printf("begin session %08x", conv)

	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows). Use nodelay=1 and resend=2 for
	// fast retransmit on the high-latency, potentially lossy DNS transport.
	conn.SetNoDelay(
		1,  // nodelay=1: flush immediately, no Nagle-like coalescing delay
		20, // interval=20ms: KCP update tick (0 causes edge-case behavior in kcp-go)
		2,  // resend=2: fast retransmit after 2 ACK gaps (0 = disabled)
		1,  // nc=1: congestion window off
	)
	conn.SetWindowSize(512, 512) // was QueueSize/2=64; larger window for high-latency DNS
	if rc := conn.SetMtu(sm.mtu); !rc {
		conn.Close()
		panic(rc)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, sm.pubkey)
	if err != nil {
		conn.Close()
		return nil, nil, nil, 0, err
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = 15 * time.Second // send PING every 15s
	smuxConfig.KeepAliveTimeout = 30 * time.Second  // declare dead after 30s (was 2 min)
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024    // default is 65536
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		rw.Close()
		conn.Close()
		return nil, nil, nil, 0, fmt.Errorf("opening smux session: %v", err)
	}

	return conn, rw, sess, conv, nil
}

// createSession closes any existing session and establishes a new one.
// Caller must NOT hold sm.mu.
func (sm *sessionManager) createSession() error {
	// Phase 1: close the old session under the write lock.
	sm.mu.Lock()
	sm.closeSessionLocked()
	sm.mu.Unlock()

	// Phase 2: create new resources without holding any lock.
	// Multiple concurrent callers are benign: only one will win phase 3.
	conn, rw, sess, conv, err := sm.createSessionUnlocked()
	if err != nil {
		return err
	}

	// Phase 3: store under the write lock. If another goroutine already
	// created a session, discard ours and keep theirs.
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.sess != nil {
		sess.Close()
		rw.Close()
		conn.Close()
		log.Printf("discarding duplicate session %08x (already have %08x)", conv, sm.conv)
		return nil
	}
	sm.conn = conn
	sm.rw = rw
	sm.sess = sess
	sm.conv = conv
	return nil
}

// closeSession closes the current session if it exists.
func (sm *sessionManager) closeSession() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.closeSessionLocked()
}

// getSession returns the current session, creating one if needed.
// Must not hold sm.mu when calling this function.
func (sm *sessionManager) getSession() (*smux.Session, uint32, error) {
	// Fast path: session already exists.
	sm.mu.RLock()
	sess, conv := sm.sess, sm.conv
	sm.mu.RUnlock()
	if sess != nil {
		return sess, conv, nil
	}

	// Slow path: createSession manages its own locking; must not hold sm.mu.
	if err := sm.createSession(); err != nil {
		return nil, 0, err
	}
	sm.mu.RLock()
	sess, conv = sm.sess, sm.conv
	sm.mu.RUnlock()
	return sess, conv, nil
}

// openStream opens a new stream, recreating the session if it appears closed.
func (sm *sessionManager) openStream() (*smux.Stream, uint32, error) {
	sess, conv, err := sm.getSession()
	if err != nil {
		return nil, 0, err
	}

	stream, err := sess.OpenStream()
	if err == nil {
		return stream, conv, nil
	}

	errStr := err.Error()
	isClosedError := errors.Is(err, io.ErrClosedPipe) ||
		strings.Contains(errStr, "closed pipe") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "use of closed network connection") ||
		err == io.EOF

	if !isClosedError {
		return nil, 0, fmt.Errorf("session %08x opening stream: %v", conv, err)
	}

	log.Printf("session %08x closed, recreating: %v", conv, err)
	// Clear the dead session only if it hasn't already been replaced by
	// another goroutine.
	sm.mu.Lock()
	if sm.sess == sess {
		sm.closeSessionLocked()
	}
	sm.mu.Unlock()

	// Delegate to getSession which will call createSession if needed.
	sess, conv, err = sm.getSession()
	if err != nil {
		return nil, 0, fmt.Errorf("recreating session: %v", err)
	}
	stream, err = sess.OpenStream()
	if err != nil {
		return nil, 0, fmt.Errorf("session %08x opening stream after recreate: %v", conv, err)
	}
	return stream, conv, nil
}

func handle(local *net.TCPConn, sm *sessionManager) error {
	stream, conv, err := sm.openStream()
	if err != nil {
		return fmt.Errorf("opening stream: %v", err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	// KCP segment must fit in one DNS name: decoded = clientID(8) + paddingByte(1) + padding(numPadding) + length(1) + payload.
	capacity := nameCapacity(domain)
	overhead := 8 + 1 + numPadding + 1
	maxPayloadInName := capacity - overhead
	if maxPayloadInName < 1 {
		return fmt.Errorf("domain %s leaves no room for payload (capacity %d)", domain, capacity)
	}
	mtu := maxPacketSize
	if maxPayloadInName < mtu {
		mtu = maxPayloadInName
	}
	log.Printf("effective MTU %d", mtu)

	// Create session manager
	sm := newSessionManager(pubkey, domain, remoteAddr, pconn, mtu)
	defer sm.closeSession()

	// Create initial session
	err = sm.createSession()
	if err != nil {
		return err
	}

	for {
		local, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sm)
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

var dialerControl func(network, address string, c syscall.RawConn) error = nil

func main() {
	// If no command-line arguments are given, try to read options from
	// environment variables, for compatibility with shadowsocks plugins.
	// ss-local -s 0.0.0.1 -p 1 -l 1080 -k password --plugin dnstt-client --plugin-opts 'doh=https://doh.example/dns-query;domain=<domain>;pubkey=<pubkey>'
	if len(os.Args) == 1 {
		pluginOpts := os.Getenv("SS_PLUGIN_OPTIONS")
		if pluginOpts != "" {
			var transportFlag, resolver, pubkey, domainStr string

			// Parse the semicolon-separated list of options.
			options := strings.Split(pluginOpts, ";")
			for _, opt := range options {
				parts := strings.SplitN(opt, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				switch key {
				case "doh":
					transportFlag = "-doh"
					resolver = value
				case "dot":
					transportFlag = "-dot"
					resolver = value
				case "udp":
					transportFlag = "-udp"
					resolver = value
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

			// Validate that we have all the required options, mimicking the shell script's checks.
			if transportFlag == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain one of: doh, dot, or udp")
				os.Exit(1)
			}
			if resolver == "" {
				remoteHost := os.Getenv("SS_REMOTE_HOST")
				remotePort := os.Getenv("SS_REMOTE_PORT")
				if remoteHost == "" || remotePort == "" {
					fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain one of: doh, dot, or udp")
					os.Exit(1)
				}
				resolver = net.JoinHostPort(remoteHost, remotePort)
			}
			if transportFlag == "-doh" {
				if !strings.HasPrefix(strings.ToLower(resolver), "https://") {
					resolver = "https://" + resolver + "/dns-query"
				}
			}
			if pubkey == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain pubkey")
				os.Exit(1)
			}
			if domainStr == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain domain")
				os.Exit(1)
			}
			if localHost == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_LOCAL_HOST environment variable not set")
				os.Exit(1)
			}
			if localPort == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_LOCAL_PORT environment variable not set")
				os.Exit(1)
			}

			// Reconstruct os.Args so the existing flag-parsing logic can be used.
			os.Args = []string{
				os.Args[0],
				transportFlag,
				resolver,
				"-pubkey",
				pubkey,
				domainStr,
				net.JoinHostPort(localHost, localPort),
			}
		}
	}

	var dohURL string
	var dotAddr string
	var pubkeyFilename string
	var pubkeyString string
	var udpAddr string
	var utlsDistribution string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-udp ADDR] (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN LOCALADDR

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000

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
	flag.StringVar(&dohURL, "doh", "", "URL of DoH resolver")
	flag.StringVar(&dotAddr, "dot", "", "address of DoT resolver")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"choose TLS fingerprint from weighted distribution")
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

	// Iterate over the remote resolver address options and select one and
	// only one.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	for _, opt := range []struct {
		s string
		f func(string) (net.Addr, net.PacketConn, error)
	}{
		// -doh
		{dohURL, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				// Disable DefaultTransport's default Proxy =
				// ProxyFromEnvironment setting, for conformity
				// with utlsRoundTripper and with DoT mode,
				// which do not take a proxy from the
				// environment.
				transport.Proxy = nil
				rt = transport
			} else {
				rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
			}
			pconn, err := NewHTTPPacketConn(rt, dohURL, 32)
			return addr, pconn, err
		}},
		// -dot
		{dotAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{
					NetDialer: &net.Dialer{
						Control: dialerControl,
					},
				}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}
			pconn, err := NewTLSPacketConn(dotAddr, dialTLSContext)
			return addr, pconn, err
		}},
		// -udp
		{udpAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr, err := net.ResolveUDPAddr("udp", s)
			if err != nil {
				return nil, nil, err
			}
			lc := net.ListenConfig{
				Control: dialerControl,
			}
			pconn, err := lc.ListenPacket(context.Background(), "udp", ":0")
			return addr, pconn, err
		}},
	} {
		if opt.s == "" {
			continue
		}
		if pconn != nil {
			fmt.Fprintf(os.Stderr, "only one of -doh, -dot, and -udp may be given\n")
			os.Exit(1)
		}
		var err error
		remoteAddr, pconn, err = opt.f(opt.s)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if pconn == nil {
		fmt.Fprintf(os.Stderr, "one of -doh, -dot, or -udp is required\n")
		os.Exit(1)
	}

	pconn = NewDNSPacketConn(pconn, remoteAddr, domain)
	err = run(pubkey, domain, localAddr, remoteAddr, pconn)
	if err != nil {
		log.Fatal(err)
	}
}
