# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-03-07

### Added

- **Multi-resolver pool** — client now accepts multiple `-doh`, `-dot`, and `-udp` flags (all repeatable); flags from different types may be mixed freely. A single `-doh` / `-dot` / `-udp` continues to work exactly as before.
- **`-resolvers-file path`** — load resolvers from a file (one per line, prefix `doh:`, `dot:`, or `udp:`; `#` comments and blank lines ignored). Flag may be repeated; all files are merged with flag-provided resolvers.
- **`-resolver-policy`** — selection policy for the pool: `round-robin`, `least-ping` (default), or `weighted-traffic`.
  - `least-ping`: round-robins among endpoints until each has at least one RTT measurement, then always prefers the lowest-RTT healthy endpoint.
  - `weighted-traffic`: selects with probability proportional to bytes received from each endpoint; falls back to round-robin until traffic is non-zero.
- **`-scan`** — pre-start scan: probes every resolver and keeps only those that return a valid tunnel response from the server. UDP endpoints are probed via a dedicated socket; DoH/DoT endpoints cannot be probed and are assumed OK with a log warning. Exits with an error if no resolver passes.
- **Background health checker** — when the pool has more than one UDP resolver, a goroutine probes each one every 15 s using a dedicated socket (separate from the traffic socket) and tracks RTT and health. After two consecutive failures an endpoint is marked unhealthy and skipped by the selection policy. All endpoints are marked healthy again on the next successful probe. If all endpoints are unhealthy, selection falls back to the full list so the tunnel does not stall.

### Changed

- Resolvers that advertise only 512-byte EDNS payload are no longer rejected with FORMERR. The server now caps response size per request (min of requester's EDNS size and server `-mtu`), so 512-only resolvers receive smaller TXT responses and the tunnel works without requiring `-mtu 512` or larger resolver support.

## [1.0.0] - 2026-03-06

First release of the dnsttEx fork. Changes since upstream (after ae95dda):

### Added
- Integration tests for concurrent connections and session management

### Changed
- Module renamed to dnsttEx
- DNS payload encoding: switched from Base32 to Base36
- DNS payload framing made more compact
- KCP: use modified implementation with 12-byte header
- Increased queue sizes; KCP misconfiguration adjusted
- smux keepalive and Poller backoff fixes

### Fixed
- Deadlock bug
- smux keepalive behavior
- Poller backoff behavior

[Unreleased]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AliRezaBeigy/dnsttEx/releases/tag/v1.0.0
