# DNS Tunnel Client - Data Flow Diagram

This document illustrates how the dnstt-client sends and receives data through the DNS tunnel.

## Architecture Overview

```
┌─────────────┐
│ Local App   │  (e.g., curl, browser, SSH client)
│ (TCP conn)  │
└──────┬──────┘
       │ TCP
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    dnstt-client                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   smux   │  │  Noise   │  │   KCP    │  │   DNS    │  │
│  │ (streams)│→ │(encrypt) │→ │(reliable)│→ │(encode)  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
       │ DoH/DoT/UDP DNS
       ▼
┌─────────────┐
│   DNS       │  (Public recursive resolver)
│  Resolver   │  (e.g., Cloudflare, Google)
└──────┬──────┘
       │ UDP DNS
       ▼
┌─────────────┐
│   Tunnel    │
│   Server    │
└──────┬──────┘
       │ TCP
       ▼
┌─────────────┐
│ Remote App  │  (e.g., HTTP proxy, SOCKS proxy, SSH server)
└─────────────┘
```

## Protocol Stack

```
Application Data (e.g., "GET / HTTP/1.1\r\n...")
    │
    ▼
smux Stream (multiplexing, session management)
    │
    ▼
Noise Protocol (end-to-end encryption: Noise_NK_25519_ChaChaPoly_BLAKE2s)
    │
    ▼
KCP (reliable datagram transport with ACKs, retransmission)
    │
    ▼
DNS Encoding (packets encoded as DNS names in queries/responses)
    │
    ▼
DoH/DoT/UDP DNS (transport layer)
```

---

## Sending Data: Client → Server

### Example: Sending "Hello" from local app to remote server

#### Step 1: Application writes data
```
Local App → TCP Connection → dnstt-client
Data: "Hello"
```

#### Step 2: smux creates stream
```
smux Session opens new stream
Stream ID: 1
Data: "Hello"
```

#### Step 3: Noise encrypts
```
Noise Protocol (Client Handshake)
- Authenticates server using public key
- Establishes encrypted channel
- Encrypted data: [encrypted "Hello"]
```

#### Step 4: KCP segments and adds reliability
```
KCP Protocol
- Segments data into packets
- Adds sequence numbers, ACKs
- Adds reliability headers
Packet: [KCP header][encrypted "Hello"]
```

#### Step 5: DNS encoding
```
DNS Encoding Process:

1. Raw packet: [KCP header][encrypted "Hello"]
   Length: ~50 bytes

2. Add ClientID (8 bytes) + padding (3 bytes) + length prefix (1 byte):
   [ClientID: 0x1234567890ABCDEF][padding: 0xE3D9A3][length: 0x05][data: "Hello"]

3. Base32 encode (no padding, lowercase):
   "ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d"

4. Split into DNS labels (max 63 bytes each):
   "ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d"

5. Append domain:
   "ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.t.example.com"

6. Create DNS query:
   DNS Query:
   - ID: 0x1234 (random)
   - Question: TXT query for "ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.t.example.com"
   - EDNS(0): UDP payload size = 4096
```

#### Step 6: Transport (DoH example)
```
HTTP POST Request:
POST https://doh.cloudflare-dns.com/dns-query HTTP/1.1
Host: doh.cloudflare-dns.com
Content-Type: application/dns-message
Accept: application/dns-message
User-Agent: (empty)

[Binary DNS message with encoded query]
```

#### Step 7: DNS resolver forwards
```
DNS Resolver → Tunnel Server (UDP DNS)
Query: TXT ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.t.example.com
```

#### Step 8: Server processes
```
Tunnel Server:
1. Decodes DNS name → extracts packet
2. KCP processes packet → delivers to Noise
3. Noise decrypts → delivers to smux
4. smux delivers to stream → forwards to remote app
```

---

## Receiving Data: Server → Client

### Example: Receiving "World" from remote server

#### Step 1: Server receives data
```
Remote App → Tunnel Server
Data: "World"
```

#### Step 2-4: Server processes (same as client, in reverse)
```
smux → Noise → KCP → DNS encoding
```

#### Step 5: Server sends DNS response
```
Tunnel Server → DNS Resolver (UDP DNS)

DNS Response:
- Answer: TXT record
- RDATA: [length-prefixed packets containing "World"]
- Encoded in Base32 within TXT record
```

#### Step 6: DNS resolver forwards to client
```
DNS Resolver → Client (DoH response)

HTTP Response:
HTTP/1.1 200 OK
Content-Type: application/dns-message

[Binary DNS message with TXT response]
```

#### Step 7: Client decodes DNS response
```
DNS Decoding Process:

1. Extract TXT record from DNS response
2. Decode Base32 → binary data
3. Extract length-prefixed packets:
   Packet 1: [length: 0x05][data: "World"]
```

#### Step 8: KCP processes
```
KCP Protocol:
- Receives packet
- Sends ACK (if needed)
- Reassembles if fragmented
- Delivers to Noise layer
```

#### Step 9: Noise decrypts
```
Noise Protocol:
- Decrypts packet
- Delivers to smux
```

#### Step 10: smux delivers to stream
```
smux Session:
- Matches packet to stream ID
- Delivers to application stream
```

#### Step 11: Application receives
```
dnstt-client → TCP Connection → Local App
Data: "World"
```

---

## Complete Example: HTTP Request/Response

### Scenario: Client sends HTTP GET request, receives response

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Local App sends HTTP request                                 │
│    GET /index.html HTTP/1.1                                     │
│    Host: example.com                                            │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. dnstt-client: smux creates stream                            │
│    Stream ID: 1                                                 │
│    Data: "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"│
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. dnstt-client: Noise encrypts                                 │
│    Encrypted: [32-byte Noise header][encrypted HTTP request]    │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. dnstt-client: KCP segments                                  │
│    Packet 1: [KCP hdr][encrypted chunk 1] (200 bytes)          │
│    Packet 2: [KCP hdr][encrypted chunk 2] (150 bytes)          │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. dnstt-client: DNS encoding                                   │
│    Query 1: aaaa1234.t.example.com (contains Packet 1)         │
│    Query 2: bbbb5678.t.example.com (contains Packet 2)         │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. DoH transport                                                │
│    POST https://doh.cloudflare-dns.com/dns-query               │
│    [DNS query 1]                                                │
│    POST https://doh.cloudflare-dns.com/dns-query               │
│    [DNS query 2]                                                │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. DNS Resolver forwards to Tunnel Server                       │
│    UDP DNS: TXT aaaa1234.t.example.com                          │
│    UDP DNS: TXT bbbb5678.t.example.com                          │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. Tunnel Server processes                                      │
│    - Decodes DNS names → extracts packets                       │
│    - KCP reassembles → delivers to Noise                        │
│    - Noise decrypts → delivers to smux                          │
│    - smux delivers to stream → forwards to remote app           │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 9. Remote App (HTTP server) receives request                   │
│    GET /index.html HTTP/1.1                                     │
│    Host: example.com                                            │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 10. Remote App sends HTTP response                             │
│     HTTP/1.1 200 OK                                             │
│     Content-Length: 1234                                        │
│     <html>...</html>                                            │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 11. Tunnel Server: Same process in reverse                     │
│     smux → Noise → KCP → DNS encoding → UDP DNS response       │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 12. DNS Resolver forwards response to client                    │
│     DoH Response: [DNS message with TXT record]                │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 13. dnstt-client: Reverse process                              │
│     DNS decode → KCP → Noise → smux → TCP → Local App           │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ 14. Local App receives HTTP response                           │
│     HTTP/1.1 200 OK                                             │
│     <html>...</html>                                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Features

### 1. Polling Mechanism
The client uses polling queries to receive data from the server:
- **Empty polling queries**: Sent periodically (500ms - 10s) to check for server data
- **Immediate polling**: After receiving data, client sends additional polls to maintain throughput
- **Polling query format**: Contains only ClientID + padding, no data payload

Example polling query:
```
DNS Query: TXT [ClientID][padding].t.example.com
```

### 2. Bidirectional Communication
- **Client → Server**: Data encoded in DNS query names
- **Server → Client**: Data encoded in DNS response TXT records
- Both directions work simultaneously (full duplex)

### 3. Reliability (KCP)
- Automatic retransmission of lost packets
- Sequence numbers and ACKs
- Congestion control
- Works over unreliable DNS transport

### 4. Encryption (Noise)
- End-to-end encryption between client and server
- Server authentication via public key
- Client authentication not required (NK pattern)
- Protocol: Noise_NK_25519_ChaChaPoly_BLAKE2s

### 5. Stream Multiplexing (smux)
- Multiple TCP connections can share one tunnel session
- Each connection gets its own smux stream
- Streams are independent and can be closed separately

---

## Data Encoding Details

### Client → Server (DNS Query)

```
Packet Structure:
┌──────────┬──────────┬──────────┬──────────┬──────────┐
│ ClientID │ Padding  │ Length   │   Data   │          │
│  (8 B)   │  (3-8 B) │  (1 B)   │  (0-223) │          │
└──────────┴──────────┴──────────┴──────────┴──────────┘
     │
     ▼ Base32 encode (no padding, lowercase)
     │
     ▼ Split into labels (max 63 bytes each)
     │
     ▼ Append domain
     │
     ▼ Create DNS query
     │
     ▼
DNS Query: TXT [encoded-name].t.example.com
```

### Server → Client (DNS Response)

```
Packet Structure:
┌──────────┬──────────┬──────────┬──────────┬──────────┐
│ Length 1 │ Packet 1 │ Length 2 │ Packet 2 │   ...    │
│  (2 B)   │  (N B)   │  (2 B)   │  (M B)   │          │
└──────────┴──────────┴──────────┴──────────┴──────────┘
     │
     ▼ Base32 encode
     │
     ▼
DNS Response: TXT [encoded-data]
```

---

## Transport Options

### DoH (DNS over HTTPS)
```
Client → HTTPS POST → DoH Resolver → UDP DNS → Tunnel Server
- Encrypted between client and resolver
- Uses standard HTTPS/TLS
- Can use uTLS for fingerprint camouflage
```

### DoT (DNS over TLS)
```
Client → TLS connection → DoT Resolver → UDP DNS → Tunnel Server
- Encrypted between client and resolver
- Uses TLS on port 853
- Can use uTLS for fingerprint camouflage
```

### UDP DNS
```
Client → UDP DNS → Resolver/Tunnel Server
- Plaintext (no encryption at transport layer)
- Only for testing
- Not covert
```

---

## Example Command and Flow

```bash
# Start client
./dnstt-client -doh https://doh.cloudflare-dns.com/dns-query \
               -pubkey-file server.pub \
               t.example.com \
               127.0.0.1:7000
```

**What happens:**
1. Client listens on `127.0.0.1:7000` for local TCP connections
2. When app connects to `127.0.0.1:7000`, client creates smux stream
3. Data flows through: smux → Noise → KCP → DNS encoding → DoH
4. Server receives via DNS resolver, processes, forwards to remote app
5. Response flows back through same layers in reverse

**Example usage:**
```bash
# In another terminal
curl --proxy http://127.0.0.1:7000/ https://example.com
```

This creates a complete tunnel from local curl → dnstt-client → DoH resolver → 
tunnel server → remote HTTP proxy → example.com, with all data encrypted 
end-to-end between client and server.

