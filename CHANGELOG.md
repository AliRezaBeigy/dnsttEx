# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.20] - 2026-03-21

### Changed

- **Server smux keepalive aligned with the client** — `acceptStreams` used **15s / 30s** (interval / timeout) while the client used **30s / 120s**. On multi-second DNS+KCP paths the server could declare the smux session dead while NREQ/replay was still recovering downstream gaps, producing hung SOCKS/HTTP or empty replies. Defaults are now **30s / 120s**, with **`DNSTT_SMUX_KEEPALIVE_INTERVAL`** and **`DNSTT_SMUX_KEEPALIVE_TIMEOUT`** on the server (same semantics as the client).

- **Lossy-path defaults for NREQ/replay copies** — Default **`DNSTT_KCP_NREQ_COPIES`** is **3** (was `2`); default **`DNSTT_KCP_REPLAY_SEND_COPIES`** is **3** (was `2`). Override with env if you need less redundant DNS traffic.

### Fixed

- **NREQ flushed between clocked `Update` ticks** — If `ikcp_update` saw **`slap < 0`**, it skipped `flush` while **`nreqList` was non-empty**; `maybeRetryNreqOnStall` then returned immediately at its `nreqList` guard, so resend requests could stall until the next interval. **`Update` now runs `flush(IKCP_FLUSH_ACKONLY)` when `slap < 0` and `len(nreqList) > 0`**, so pending NREQ reaches the server promptly.

- **Idle-tail NREQ when `lastRcvNxtAdvanceMs == 0`** — The idle probe treated **`lastRcvNxtAdvanceMs == 0` as “never advanced”**, but that value is also valid when **`currentMs()` is still `0`** at the first in-order delivery (sub‑millisecond after process start). **`rcv_nxt` has already moved** in that case, so idle recovery must still run. The guard is now **`lastRcvNxtAdvanceMs == 0 && rcv_nxt == 0`** (true cold start only).

## [1.5.19] - 2026-03-21

### Changed

- **No-data DNS responses prefer `0x01` hint over `0x00` empty data** — When `sendLoop` has no downstream tunnel bytes to pack, the server now emits a **`0x01` missing-hint frame** whenever it fits in the per-request TXT payload budget (instead of defaulting to `0x00` with no body, which looked like an “explicit empty marker” in client logs). If the hint cannot fit (extremely tight response size), the server still falls back to `0x00` empty.

### Fixed

- **Informational hint when SN estimate is unknown** — Before any downstream PUSH has been observed for hint bookkeeping, the server still sends a valid **`0x01` frame with `suggested_count=0`** (TTL debounce applies). **`ApplyServerMissingHint` treats `suggested_count=0` as non-actionable** (no NREQ), avoiding bogus resend storms while preserving typed “no useful data” signaling on the wire.

## [1.5.18] - 2026-03-21

### Changed

- **Downstream TXT framing now uses a mandatory first-byte flag** — Tunnel responses are now framed as `0x00` + payload bytes (including empty payload as one-byte frame `0x00`) or `0x01` + hint metadata. This replaces the prior special-case `{0x00}` empty marker and gives the client an explicit typed control channel from server to client inside TXT payload bytes.

### Added

- **Server missing-hint frame (`0x01`) and client fast NREQ scheduling** — Server can emit a structured hint frame (`first_missing_sn_full`, `highest_sent_sn_full`, `suggested_count`, `hint_ttl_ms`) when no downstream payload is sent. The client decodes this hint, estimates likely-missed downstream range, debounces repeated hints by TTL, and immediately schedules targeted NREQ via KCP instead of waiting for inferred reorder gaps.

## [1.5.17] - 2026-03-21

### Fixed

- **Client NREQ for trailing downstream loss (“idle tail”)** — When the **last** one or more downstream PUSH segments are lost and **no later segment arrives**, `rcv_buf` stays empty and there is no `sn > rcv_nxt` gap to schedule NREQ, so the client could hang forever waiting for a final fragment. **`maybeRetryNreqOnStall` now emits bounded speculative NREQ** when `PeekSize() < 0`, `rcv_buf` is empty, and **`rcv_nxt` has not advanced for `DNSTT_KCP_NREQ_IDLE_HEAD`** (default **250ms**; `0` disables). At most **3** such probes per stalled **`rcv_nxt`**; counters reset when `rcv_nxt` advances. The previous idle path required **`lastSndPushOutMs > lastRcvNxtAdvanceMs`**, which only helped when the **client** had recently sent PUSH (e.g. SOCKS dial), not pure server→client tail loss.

## [1.5.16] - 2026-03-21

### Fixed

- **NREQ replay preserves KCP PUSH `frg` (fragment index)** — Re-encoded replay PUSH segments always used **`frg=0`**. In KCP **message mode** (`stream==0`), a single logical message split across multiple MSS-sized PUSH segments relies on **`frg`** for reassembly; wrong `frg` after replay left the client unable to complete `Recv` even when every `sn` had been delivered, matching “recv seq gap” / stalled SOCKS symptoms on multi-segment downstream. **`downstreamReplay` now stores `(payload, frg)` per full `sn`**, and **`encodeResendPush` copies the stored `frg`**. **`SetOutboundPushHook`** is now **`func(sn uint32, frg uint8, payload []byte)`** so the server cache matches what was actually sent.

## [1.5.15] - 2026-03-21

### Fixed

- **`NREQ` / `NMIS` wire encoding (compact 12-byte header)** — The header only carries **two bits** of command (`cmd` in the high nibble of byte 2), so only four wire command values exist (`PUSH`/`ACK`/`WASK`/`WINS`). Emitting logical `IKCP_CMD_NREQ` (85) or `IKCP_CMD_NMIS` (86) via `(cmd−81)<<6` **collided** with `WINS` on the wire; peers decoded resend requests as window-tell frames, so the server never ran `handleDownstreamNREQ`, replay stayed idle, and the client kept retrying while stuck on `recv seq gap`. **`NREQ` and `NMIS` now encode as `WINS` with reserved `frg` markers** (`60` / `61`); `Input`/`encodeWireHeader` map those back to 85/86. **Client and server must both run this build** (or stay on a matching pair); mixed with a peer that lacks this mapping, extension frames are misinterpreted.

## [1.5.14] - 2026-03-21

### Added

- **`IKCP_CMD_NMIS` (86) — server replay miss notify** — When the client’s `NREQ` asks for a head downstream segment that is **not** in `downstreamReplay`, the server sends a compact no-payload `NMIS` frame (same 16-bit `sn` form as `NREQ`, duplicated `DNSTT_KCP_REPLAY_SEND_COPIES` times like replay). The client accepts `NMIS`, expands `sn` with `rcv_nxt`, and logs a throttled line (`server replay miss` / `missing_sn`) so empty DNS polls are not mistaken for a silent server. **`DNSTT_KCP_REPLAY_MISS_NOTIFY=0`** (or `false` / `off` / `no`) on the **server** disables `NMIS` for peers on an older client that rejects unknown KCP command bytes.

### Changed

- **Downstream replay capacity (server)** — Default replay cache raised to **8192** entries and **8 MiB** total payload (was 2048 / 2 MiB). Override with **`DNSTT_KCP_REPLAY_MAX_ENTRIES`** and **`DNSTT_KCP_REPLAY_MAX_BYTES`** (bounded clamps apply).

### Fixed

- **NREQ replay when the head segment is missing** — If the first missing `sn` is not in the replay map, the server no longer replays **later** segments for that `NREQ` (they cannot unblock `rcv_nxt` and only added duplicate out-of-order downstream). Combined with `NMIS`, the client gets an explicit signal instead of endless “empty” poll responses.

## [1.5.13] - 2026-03-21

### Fixed

- **Server downstream replay hooks before first flush** — `newUDPSession` started the per-session updater (`SystemTimedSched.Put(sess.update, …)`) **before** installing `SetOutboundPushHook` / `SetResendRequestHandler`. Early downstream PUSH segments (`sn` 0, 1, 2, …) could therefore leave the server **without** being stored in `downstreamReplay`, so client NREQ could not replay a lost first segment and logs showed `next_expected_sn=0` or `2` while later `sn` kept arriving. Replay setup now runs **before** `postProcess` and the updater.

## [1.5.12] - 2026-03-21

### Fixed

- **Post-process plaintext replay capture removed** — Re-parsing encrypted-path buffers with **`snd_nxt − pushCount`** as anchor was unreliable when a single KCP output buffer mixed **ACK / NREQ** before **PUSH**, or when **MTU splitting** separated frames. Mis-keyed capture could **overwrite** correct `bySN` entries from **`onOutboundPush`**, leaving NREQ unable to replay the real hole (client stuck on `rcv_nxt`, duplicate later PUSHes). Downstream replay is again populated **only** from `onOutboundPush` (authoritative `segment.sn` per PUSH). **`resolveWireSN`** / NREQ lap resolution are unchanged.

## [1.5.11] - 2026-03-21

### Fixed

- **Replay capture anchor per output buffer** — Plaintext capture used `expandSN16` with anchor **0** at the start of **every** post-process buffer. For any lap after **65536** downstream segments, the same 16-bit wire value (e.g. `2`) maps to a **different** full `sn`; anchor **0** then filed payloads under the wrong `bySN` key, so NREQ could not find the real missing segment and the client saw endless duplicate PUSHes while stuck on an earlier `rcv_nxt`. Each enqueue now passes **`replayAnchor = snd_nxt − pushCount`** at post-process time (and `enqueuePlainKCP` uses the same rule with the live `snd_nxt`), matching `onOutboundPush` keys through long-lived sessions.

## [1.5.10] - 2026-03-21

### Fixed

- **Downstream replay capture vs wire** — The server still mirrored PUSH payloads only via `onOutboundPush` inside `kcp.flush`. The post-process path now **parses the plaintext KCP blob again immediately before encryption** and calls the same `downstreamReplay.Add` for every PUSH. That keeps the NREQ replay map aligned with bytes that actually leave the machine (including coalesced multi-segment outputs), closing holes where `rcv_nxt==0` but `sn` 0/1 were missing from the cache even though they had been sent.

## [1.5.9] - 2026-03-21

### Fixed

- **NREQ replay lookup when server `snd_nxt` is far ahead of client `rcv_nxt`** — Resolving the wire `sn` with `expandSN16(snd_nxt, wire)` could pick the wrong 64K lap (e.g. **65536** instead of **0** when the replay map only holds **0..n**). The server now maps NREQ’s 16-bit `sn` by scanning laps **0, 65536, …** and taking the first key present in the downstream replay with `sn < snd_nxt` (or any lap when `snd_nxt==0`).

## [1.5.8] - 2026-03-21

### Fixed

- **16-bit KCP `sn`/`una` on wire vs unbounded counters** — Headers only carry the low 16 bits of sequence numbers while `rcv_nxt` / `snd_nxt` grow as `uint32`. After enough segments, a legitimate next segment (e.g. wire `0` when `rcv_nxt==65536`) was misclassified as a duplicate and dropped, leaving a permanent hole and endless NREQ/polls.

- **`parse_data` duplicate short-circuit skipped reorder drain** — A segment with `sn < rcv_nxt` returned before moving `rcv_buf` → `rcv_queue`, so a duplicate could delay processing already-buffered in-order data. The reorder pass now always runs (`advanceRcvBufToQueue`), shared with `Recv`.

## [1.5.7] - 2026-03-21

### Fixed

- **Replay of zero-length downstream PUSH (server)** — Outbound replay hooks and NREQ skipped `len==0` PUSH bodies, so a valid empty KCP PUSH at `sn==0` was never cached and could not be resent; NREQ still replayed `sn` 1+, producing endless duplicate small downstream while the client stayed at `rcv_nxt==0`. Empty PUSHes are now recorded and replayed; NREQ uses map presence, not payload length, to decide resend.

## [1.5.6] - 2026-03-21

- **Lossy-path redundancy for NREQ/replay** — Each flush emits `DNSTT_KCP_NREQ_COPIES` (default `2`) identical NREQ segments so one dropped upstream query is less likely to lose the whole resend request. While a reorder hole persists (`rcv_buf` ahead of `rcv_nxt`, including mid-stream gaps such as missing `sn` 6–9), stall retries are spaced by at most `DNSTT_KCP_NREQ_STALL_CAP` (default `150ms`; legacy env `DNSTT_KCP_NREQ_BOOTSTRAP_INTERVAL`). The server queues each replayed PUSH `DNSTT_KCP_REPLAY_SEND_COPIES` times (default `2`) per NREQ so downstream answers get duplicate chances through DNS.

### Fixed

- **NREQ idle-head (SOCKS / single lost downstream segment)** — With server `SetAssumeDeliveredAfterSend` and client `SetSuppressOutgoingACK`, a **sole** lost downstream PUSH leaves `rcv_buf` empty (no later segment to infer a gap), so NREQ never ran and SOCKS could hang on `ReadAck` until smux keepalive. The client now sends NREQ for the next segment window after `DNSTT_KCP_NREQ_IDLE_HEAD` (default `250ms`) with no `rcv_nxt` progress following an on-wire PUSH. Set `DNSTT_KCP_NREQ_IDLE_HEAD=0` to disable.

### Changed

- **Downstream replay eviction (server)** — The replay cache previously evicted the **oldest** stored `sn` first (FIFO). While the client was stuck on a **low** missing `sn`, the server kept sending **newer** PUSHes; FIFO then dropped the very payloads NREQ asked for, so replays were empty and gaps never closed. Eviction now drops the **highest** `sn` first (KCP-style compare via `_itimediff`), and default capacity is raised (`2048` entries / `2 MiB` bytes).

## [1.5.5] - 2026-03-21

### Added

- **KCP recv gap diagnostics** — `internal/kcp` SNMP adds `RcvReorderGap` and `RcvBeyondWindow`. Set `DNSTT_KCP_RECV_GAP=1` to log when a downstream PUSH has `sn > rcv_nxt`; optional `DNSTT_KCP_RECV_GAP_VERBOSE=1` logs every such segment (default: once per stalled `rcv_nxt`).

- **NREQ stall retries (client)** — While out-of-order segments remain in `rcv_buf`, the client re-sends `IKCP_CMD_NREQ` on a timer (default first spacing `400ms`, exponential backoff capped at `8s`), scheduled from `UDPSession.update()` so retries continue even when DNS polls carry no new KCP payload. Env: `DNSTT_KCP_NREQ_INTERVAL`, `DNSTT_KCP_NREQ_INTERVAL_MAX`. Backoff resets when `rcv_nxt` advances.

### Changed

- **NREQ gap log wording** — Sequence-gap lines now include `missing_streak` and the half-open `sn` range for easier reading.

## [1.5.4] - 2026-03-21

### Added

- **KCP downstream resend (NREQ)** — New control `IKCP_CMD_NREQ` (85): on a downstream sequence gap the client can send one compact request (`first_sn`, count) instead of per-segment ACKs. The server keeps a bounded replay cache of recent outbound PUSH payloads and re-encodes missing segments on request. **Client:** NREQ enabled by default; set `DNSTT_KCP_NREQ=0` if the server does not accept cmd 85. **Server:** replay enabled by default; set `DNSTT_KCP_REPLAY=0` to disable.

## [1.5.3] - 2026-03-20

### Added

- **Optional plaintext transport (no Noise)** — Client `-no-noise` sends a 3-byte preamble then runs smux directly on KCP (skips Noise NK). The server always accepts this negotiation when offered. Default remains Noise-only for clients that do not send the preamble; this mode removes crypto and server authentication from the tunnel (dangerous). Wire negotiation uses an impossible Noise first-message length (`u16(1)` + mode byte) so existing Noise clients remain compatible.

### Changed

- **SOCKS5 tunnel warmup** — SOCKS mode now completes the Noise+smux handshake before opening the local listener (unless `DNSTT_TUNNEL_WARMUP=async` or `off`), so browsers that open many parallel connections no longer all block on the first handshake. TCP forward mode still uses async warmup by default.

## [1.5.2] - 2026-03-20

### Changed

- **FEC disabled by default** — `DNSTT_FEC_DATA` and `DNSTT_FEC_PARITY` default to 0 on client and server. Set e.g. `DNSTT_FEC_DATA=2` and `DNSTT_FEC_PARITY=1` on both sides when you want Reed–Solomon parity on lossy links (values must match).

### Fixed

- **Client DNS `sendLoop` batching vs framing** — Per-query tunnel budget now matches upstream framing (`8+1+2` prefix plus `1+len` per segment) so the length byte is not double-counted. This removes a tight stash/poll/unstash loop on very low request MTU that could flood resolvers with useless queries.


## [1.5.1] - 2026-03-20

### Changed

- **Per-query response-size hint for all tunnel queries** — Normal client queries now always carry an unsigned 2-byte max-response hint in-band (`[clientID][0xFD][hint_hi][hint_lo][frame...]`) for both idle polls and data-carrying queries, so server response sizing no longer depends on recursive resolver behavior for OPT Class.

- **Server response sizing is stateless per request** — Removed server-side cached client response-hint state; each response is now capped directly from the current query’s in-band hint (with existing bounds), eliminating cross-query cache assumptions.

## [1.5.0] - 2026-03-20

### Changed

- **Optional no-ACK downstream mode (experimental)** — Added KCP toggles to support a one-way downstream model where the server can treat sent `PUSH` segments as delivered immediately (`SetAssumeDeliveredAfterSend`) and the client can suppress outgoing ACK generation (`SetSuppressOutgoingACK`). This is intended for constrained paths where client→server return traffic is expensive.

- **Loss-avoidance via backpressure in no-retransmit paths** — The KCP post-processing enqueue path now avoids silent drops when assume-delivered mode is active; packets are backpressured instead of discarded. This prevents unrecoverable stream stalls that would otherwise occur when retransmission is disabled.

- **Queue path hardening against silent drops** — `QueuePacketConn` enqueue operations now prefer backpressure over drop-on-full behavior, and downstream stash handling in server `sendLoop` now uses a non-dropping backpressure helper. This reduces hidden packet loss under burst load.

## [1.4.4] - 2026-03-20

### Changed

- **MTU pruning for faster convergence** — When a candidate size is definitively rejected (verification/permanent failure), the client now marks all larger sizes as failed in the same discovery run. This follows MTU monotonicity (if one tier is truly too large, larger tiers are too) and reduces wasted timeout rounds.

- **SOCKS CONNECT failure classification (client)** — In `-tunnel socks` mode, client-side CONNECT now distinguishes tunnel/protocol ACK read failures from remote dial rejection. ACK read/protocol failures are reported as SOCKS server failure, while explicit remote dial reject remains host unreachable.

- **SOCKS relay ACK behavior hardening (server)** — In SOCKS tunnel mode, server now best-effort returns explicit failure ACK on open-parse/unsupported-network paths (instead of closing silently), reducing client-side "closed pipe while waiting for ACK" ambiguity.

## [1.4.3] - 2026-03-20

### Changed

- **MTU discovery faster convergence (`3/3` in one timeout window)** — For each candidate response size and QNAME size, the client now sends all remaining required probe attempts concurrently in the same round instead of waiting for one probe per round.

- **Downstream empty marker semantics (`TXT(0x00)`)** — The client now treats a single-byte `0x00` TXT payload as an explicit empty-response marker (poll/ACK) rather than a tunnel data packet.

- **Latency-first downstream response utilization** — In server `sendLoop`, when per-client collection lock contention occurs (`TryLock` fails), the server now performs a zero-wait dequeue probe (`Unstash` then `OutgoingQueue`) before falling back to the empty marker. This keeps low latency while reducing missed chances to return real data.

- **non-blocking dequeue probe before empty fallback** — In the normal response collection path, when the wait timer expires with no packet selected, the server now does one last zero-wait queue check before encoding `TXT(0x00)`. This improves data return opportunity under high loss/reordering races without changing MTU/truncation safety behavior.

## [1.4.2] - 2026-03-19

### Added

- **Scan and MTU discovery progress logs** — `scan` and `-scan` log periodic progress (resolver count and UDP pass count for bulk `scan`). MTU discovery logs each response-size and QNAME trial so long probes are visibly advancing; tunnel startup logs when discovery begins for N resolvers.

- **Configurable KCP segment drop (`DNSTT_KCP_DEAD_LINK`)** — Max retransmits per segment before it is dropped (default 20). Use 50–100 on high-latency or lossy networks so segments are not dropped too early. Both client and server read this env var.

- **FEC (Forward Error Correction) configurable and on by default** — `DNSTT_FEC_DATA` and `DNSTT_FEC_PARITY` control KCP FEC shards on client and server. Default is (2, 1): 2 data + 1 parity shard for lossy paths. Set both to 0 to disable FEC.

- **Configurable queue size (`DNSTT_QUEUE_SIZE`)** — Send/receive queue size per peer (default 1024). Use 2048–4096 on high-latency or lossy networks to reduce drops when KCP retransmits. Applied in turbotunnel (client and server).

### Changed

- **KCP: drop segment only on max retransmits, keep session open** — When a segment hits the dead-link retry limit, only that segment is dropped from the send buffer and the session stays open. Other traffic and other clients (e.g. middleware/xray) are unaffected; no session close.

## [1.4.1] - 2026-03-17

### Changed

- **MTU discovery stricter and more resilient** — Each candidate response/QNAME size must succeed **three** consecutive probe exchanges before it is accepted. After a **read timeout**, the client retries that trial **once** (extra send/read). Discovery still picks the largest working server response size and largest working QNAME by probing sizes in descending order.

- **`internal/kcp` rebased on xtaci/kcp-go v5.6.71** — Vendored KCP stack updated from upstream; brings current session layer, ring buffers, scheduling, and related fixes while keeping dnstt-specific behavior.

## [1.4.0] - 2026-03-17
### Changed
- **Default tunnel mode is SOCKS** — Client and server default `-tunnel` to `socks` instead of `tcp`.

### Added
- **Client-side SOCKS tunnel mode (`-tunnel socks`)** — The client runs a SOCKS5 server and sends the destination per stream; the server dials the requested target directly to reduce extra SOCKS/SSH handshakes crossing the DNS tunnel.

## [1.3.3] - 2026-03-15

### Changed

- **Client MTU is QNAME length, not UDP payload** — `-mtu` and per-resolver client MTU discovery now limit the **question name wire size** (RFC 1035 QNAME, max 255 octets), matching common DPI behavior. Payload sizing, probes, and sends cap by QNAME; full DNS message size may still be larger (header, OPT, etc.). Discovery log reports `max query QNAME N bytes`. **Breaking:** manual `-mtu` values tied to old full-wire sizes (e.g. 280) must be replaced with a QNAME limit (≤ 255).

### Added

- **`-send-parallel` (client)** — When using multiple resolvers, the same packet can be sent to N resolvers in parallel so at least one may succeed. Use `-send-parallel 3` (for example) with a resolver pool; the client builds one query (sized to the minimum MTU of the chosen resolvers) and sends it to that many endpoints at once. The send succeeds if any WriteTo succeeds. Default is 1 (single resolver per send). Sending the same tunnel data multiple times is safe; the server handles duplicates.

- **`scan` subcommand (client)** — `dnstt-client scan -resolvers-file … -scan-checks N -scan-retry R DOMAIN out.txt` (or `-domain DOMAIN` with a single output path) probes each **UDP** resolver with the usual PING/PONG health check and writes passing lines to a file. `-scan-retry` retries failed checks before giving up on that round. Large IP lists use **bounded parallelism** (`-scan-parallel`, default 64) and **one UDP socket per probe** (not two × N at once), avoiding Windows bind failures (“buffer space / queue full”).

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

[Unreleased]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.20...HEAD
[1.5.20]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.19...v1.5.20
[1.5.19]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.18...v1.5.19
[1.5.18]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.17...v1.5.18
[1.5.17]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.16...v1.5.17
[1.5.16]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.15...v1.5.16
[1.5.15]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.14...v1.5.15
[1.5.14]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.13...v1.5.14
[1.5.13]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.12...v1.5.13
[1.5.12]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.11...v1.5.12
[1.5.11]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.10...v1.5.11
[1.5.10]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.9...v1.5.10
[1.5.9]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.8...v1.5.9
[1.5.8]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.7...v1.5.8
[1.5.7]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.6...v1.5.7
[1.5.6]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.5...v1.5.6
[1.5.5]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.4...v1.5.5
[1.5.4]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.3...v1.5.4
[1.5.3]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.2...v1.5.3
[1.5.2]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.4.4...v1.5.0
[1.4.4]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.4.3...v1.4.4
[1.4.3]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.3.3...v1.4.0
[1.3.3]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AliRezaBeigy/dnsttEx/releases/tag/v1.0.0
