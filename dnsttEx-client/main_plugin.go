// Shadowsocks plugin compatibility: parse SS_PLUGIN_OPTIONS and set os.Args.
// See main.go for package documentation.

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// applyShadowsocksPluginOptsIfNeeded runs when no command-line arguments are
// given. It reads SS_PLUGIN_OPTIONS (and related env vars) and reconstructs
// os.Args so the rest of the program can use the same flag parsing.
// Exits the process on validation errors.
func applyShadowsocksPluginOptsIfNeeded() {
	if len(os.Args) != 1 {
		return
	}
	pluginOpts := os.Getenv("SS_PLUGIN_OPTIONS")
	if pluginOpts == "" {
		return
	}

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
