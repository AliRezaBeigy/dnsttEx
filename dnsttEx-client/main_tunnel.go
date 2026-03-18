// Tunnel setup and run: build endpoints, MTU discovery, start listener.
// See main.go for package documentation.

package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"dnsttEx/dns"
	"dnsttEx/turbotunnel"

	utls "github.com/refraction-networking/utls"
)

// runTunnel builds resolver endpoints, optionally scans and discovers MTU,
// then runs the tunnel (listener + session manager). Caller must have already
// parsed flags and validated domain, localAddr, pubkey, and specs.
func runTunnel(
	domain dns.Name,
	localAddr *net.TCPAddr,
	pubkey []byte,
	utlsClientHelloID *utls.ClientHelloID,
	specs []resolverSpec,
	resolverPolicy string,
	doScan bool,
	scanChecks int,
	clientMTUFlag int,
	sendParallel int,
	tunnelMode string,
) error {
	endpoints := make([]*poolEndpoint, 0, len(specs))
	for _, spec := range specs {
		ep, _, err := buildEndpointFromSpec(spec, utlsClientHelloID)
		if err != nil {
			return fmt.Errorf("resolver %s %s: %w", spec.typ, spec.addr, err)
		}
		endpoints = append(endpoints, ep)
	}

	if doScan {
		if scanChecks < 1 {
			scanChecks = 1
		}
		if scanChecks > 20 {
			scanChecks = 20
		}
		log.Printf("Scan: sending PING to %d resolver(s) (%d check(s) each)", len(endpoints), scanChecks)
		passed := scanResolvers(endpoints, domain, 8*time.Second, scanChecks, 0)
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
			return fmt.Errorf("no resolvers passed -scan; check your resolver list and that the server is reachable")
		}
		log.Printf("Scan: %d/%d resolver(s) responded with PONG", len(passed), len(endpoints))
		endpoints = passed
	}

	mtuTimeout := mtuProbeTimeout()
	log.Printf("MTU discovery: starting for %d resolver(s); watch below for per-resolver progress", len(endpoints))
	var wg sync.WaitGroup
	for _, ep := range endpoints {
		ep := ep
		wg.Add(1)
		go func(ep *poolEndpoint) {
			defer wg.Done()
			discoverMTU(ep, domain, mtuTimeout, clientMTUFlag)
		}(ep)
	}
	wg.Wait()
	if clientMTUFlag > 0 {
		log.Printf("Using client max query QNAME length %d bytes (-mtu)", clientMTUFlag)
	}

	var kept []*poolEndpoint
	for _, ep := range endpoints {
		if ep.probeConn == nil {
			kept = append(kept, ep)
			continue
		}
		maxResp, maxReq := ep.getMaxSizes()
		if maxResp > 0 && maxReq > 0 {
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
		return fmt.Errorf("no resolvers left after MTU discovery (every UDP resolver failed response-size probes)")
	}

	var remoteAddr net.Addr
	var pconn net.PacketConn
	var effectiveMaxResponse, effectiveMaxRequest int

	if len(endpoints) == 1 {
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
	if tunnelMode == "socks" {
		return runSocks(pubkey, domain, localAddr, remoteAddr, pconn)
	}
	return run(pubkey, domain, localAddr, remoteAddr, pconn)
}
