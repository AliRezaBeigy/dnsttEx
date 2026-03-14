# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Client MTU is QNAME length, not UDP payload** — `-mtu` and per-resolver client MTU discovery now limit the **question name wire size** (RFC 1035 QNAME, max 255 octets), matching common DPI behavior. Payload sizing, probes, and sends cap by QNAME; full DNS message size may still be larger (header, OPT, etc.). Discovery log reports `max query QNAME N bytes`. **Breaking:** manual `-mtu` values tied to old full-wire sizes (e.g. 280) must be replaced with a QNAME limit (≤ 255).

### Added

- **`scan` subcommand (client)** — `dnstt-client scan -resolvers-file … -scan-checks N -scan-retry R DOMAIN out.txt` (or `-domain DOMAIN` with a single output path) probes each **UDP** resolver with the usual PING/PONG health check and writes passing lines to a file. `-scan-retry` retries failed checks before giving up on that round.

- **SERVFAIL-aware resolver pool** — On **SERVFAIL** (rcode 2) for tunnel traffic, the client no longer burns NXDOMAIN retries on the same resolver; it notifies the pool (`ReportServfail`), triggers a poll, and lets KCP retransmit. Successful tunnel responses call `ConfirmDataPath`. Endpoints with repeated SERVFAIL are treated as **cold** for selection (similar to stale data-path), so traffic shifts toward resolvers that actually forward authoritative answers.

### Fixed

- **MTU discovery drops useless resolvers** — UDP endpoints that finish MTU discovery with **max response wire 0** (no successful server-size probe) are closed and removed from the pool so they are not selected; they cannot deliver tunneled DNS answers.

- **In-flight cap vs non-NOERROR responses** — The client decrements the data-query in-flight counter on **every** DNS response (including SERVFAIL, truncation, etc.), so `sendLoop` no longer stalls at the cap when the resolver answers with rcode ≠ 0.

## [1.3.2] - 2026-03-10

### Added

- **In-band response-size hint (mode byte 0xFE)** — Client embeds the discovered max response size directly in the QNAME payload of poll queries. This survives recursive resolvers (e.g. Google 8.8.8.8) that rewrite the OPT Class field, which previously caused the server to build oversized responses that got truncated on the return path. The server stores the minimum hint per client so responses are safe across all resolvers in a pool.

## [1.3.1] - 2026-03-10

### Changed

- **Reduced `maxResponseDelay` from 1s to 500ms** — DNS chains with high intermediate latency (e.g. `.ir` TLD where root→TLD→NS hops consume 200-500ms) were exceeding recursive resolver timeout budgets, causing dropped responses. The lower default keeps total chain time well within limits. Override at runtime with `DNSTT_RESPONSE_DELAY` (e.g. `"200ms"`).
- **64 parallel sendLoop goroutines** — The server previously used a single goroutine to build and send all DNS responses sequentially; one slow client could block hundreds of others. Now 64 goroutines drain the work channel concurrently, eliminating this bottleneck for production deployments. Configurable via `DNSTT_SEND_LOOPS`.

## [1.3.0] - 2026-03-10

### Added

- **Concurrent MTU probing** — MTU discovery now sends all probe sizes (both server and client directions) concurrently in each round with up to 2 retry rounds, significantly reducing startup time when the pool has many resolvers.
- **In-flight query management** — Client limits concurrent data-carrying DNS queries in flight to prevent flooding the resolver. Low-MTU paths get a tighter cap (4); normal paths use 32. Configurable via `DNSTT_INFLIGHT_CAP` environment variable (0 = no limit).
- **NXDOMAIN retry** — When the client receives NXDOMAIN for a data query, it re-queues the last batch and retries up to 3 times before dropping.

### Changed

- **Server returns NOERROR for non-TXT queries** — Instead of NXDOMAIN, the server now returns NOERROR with no payload when resolvers probe with A/AAAA (QTYPE minimization per RFC 7816), allowing them to retry with the correct TXT type.
- **Server returns NOERROR for QNAME-minimized queries** — Zone-apex and partial-name queries now get NOERROR (no payload) so resolvers continue with the full QNAME instead of giving up on NXDOMAIN.
- **Server PONG sends exact requested payload** — MTU probe responses now contain exactly the requested number of payload bytes (capped by response size limit), instead of computing a target wire size.
- **Minimum KCP MTU lowered to 13** — Supports low-MTU DNS paths (e.g. 128-byte request limit) where each KCP segment must fit inside one small DNS query.
- **Server avoids empty TXT responses** — Sends a 1-byte payload instead of empty TXT so public resolvers (e.g. Google 8.8.8.8) do not reject the response.

### Fixed

- **Low-MTU data transfer** — Fixed data transfers on constrained DNS paths by lowering the minimum KCP MTU and adding in-flight query throttling.
- **Session management** — Prevented duplicate handshakes and ensured packet connections signal closure properly.
- **Client DNS transport hardened** — Fixed handling of lossy, reordered, and truncated DNS responses discovered through new chaos-relay integration tests.
- **Probe creation and MTU discovery** — Fixed probe message construction, client MTU calculation, and server PONG response handling.
- **Random ID generation** — Properly handle errors from `crypto/rand` when generating DNS probe message IDs.

## [1.2.1] - 2026-03-07

### Fixed
- **Fix wrong pong response** — distinguish MTU probe (9-byte body) from simple PING (7-byte) for PONG response

## [1.2.0] - 2026-03-07

### Added

- **Per-resolver MTU discovery** — At client startup (after optional `-scan`), the client discovers for each resolver: (1) **server MTU**: max DNS response size that still gets through (PING with increasing response size until no answer); (2) **client MTU**: max request size that still gets a PONG (PING with increasing request size until no answer). Results are stored per endpoint and the client requests that the server cap responses via OPT Class so resolvers that only support small packets (e.g. 512 bytes) work without manual tuning.
- **Client `-mtu N`** — Cap the maximum DNS response size in bytes. When set, overrides the discovered limit so the client never asks the server for responses larger than N (0 = use discovered per-resolver limit).

### Changed

- **Server PING handling** — PING probes may optionally include a 2-byte requested response size (big-endian). When present, the server responds with that many bytes of payload instead of the literal "PONG", so the client can probe which response sizes the resolver allows.

## [1.1.1] - 2026-03-07

### Added

- **Resolver file: bare IP/host** — lines in `-resolvers-file` that are a plain IP or hostname are now accepted and treated as `udp:host:53`.
- **Probe and poll cache bust** — health-check PING and idle poll queries now include random bytes in the payload so each query has a unique DNS name, avoiding stale responses from resolver or DNS cache.
- **Resolver pool integration tests** — tests for probe round-trip (PONG response) and for the health checker marking unresponsive resolvers unhealthy so the pool keeps using only healthy ones.
- **Resolver pool status logging** — the client logs a one-line summary to the console after each health check (and at startup): how many resolvers are healthy, which are unhealthy, and which resolver is currently selected (including RTT for `least-ping`). When all are unhealthy it logs that no traffic is being sent to avoid network burst.

### Changed

- **No traffic when all resolvers unhealthy** — when every resolver in the pool is unhealthy, the pool no longer falls back to sending to the full list. It sends nothing so the network is not burst with traffic to unresponsive resolvers; send failures trigger the existing backoff and status log shows "selected: none (all unhealthy, not sending to avoid network burst)".

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

[Unreleased]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.3.2...HEAD
[1.3.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AliRezaBeigy/dnsttEx/releases/tag/v1.0.0
