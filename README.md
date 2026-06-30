# Packet Analyzer DPI Engine

This project is a defensive, offline deep-packet-inspection engine for traffic captured on a network you administer. It reads classic and modified PCAP files and separates packet decoding, flow state, application detection, policy, and enforcement.

## Architecture

```text
PCAP reader
  -> Ethernet + VLAN
  -> IPv4 / IPv6 + extension headers
  -> TCP / UDP
  -> canonical bidirectional flow table
  -> TCP sequence reassembly
  -> HTTP / TLS ClientHello / DNS classifiers (UDP and length-prefixed TCP DNS)
  -> file-backed hostname, IP, client-block, and throttling policy
  -> report-only enforcement adapter
```

Important TLS boundary: the ClientHello can expose SNI (the hostname) and ALPN. HTTPS paths, headers, bodies, and responses remain encrypted. ECH can hide SNI. UDP/443 is identified as QUIC, but QUIC Initial decryption and hostname extraction are not implemented.

## Build

With CMake:

```powershell
cmake -S . -B build
cmake --build build
```

With the MinGW compiler currently installed on this machine:

```powershell
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src\main.cpp src\pcap.cpp src\ethernet.cpp src\ipv4.cpp src\ipv6.cpp src\tcp.cpp src\udp.cpp src\dns.cpp src\http.cpp src\tls.cpp src\flow.cpp src\policy.cpp src\policy_loader.cpp src\stats.cpp src\dpi.cpp -o packetanalyzer.exe
```

## Run

Analyze the default capture:

```powershell
.\packetanalyzer.exe
```

If `policy.rules` exists in the current directory, it is loaded automatically.
Use `--no-policy-file` for raw analysis without saved policy rules.

Analyze another capture and simulate blocking a hostname and all its subdomains:

```powershell
.\packetanalyzer.exe captures\tls.pcap --block google.com
```

Mark flows blocked by an exact server IP:

```powershell
.\packetanalyzer.exe captures\tls.pcap --block-ip 148.51.155.48
```

Simulate quota exhaustion and throttling:

```powershell
.\packetanalyzer.exe captures\sample.pcap --quota-bytes 1000000 --throttle-kbps 128
```

Load a dedicated policy file:

```powershell
.\packetanalyzer.exe captures\http_get.pcap --policy policy.rules
```

## Policy rules file

Put interview/demo rules in `policy.rules`:

```text
# Block a website and all subdomains.
block-host neverssl.com

# Block one exact destination/server IP.
block-ip 148.51.155.48

# Block all detected traffic from a client/subscriber.
block-client 10.177.124.95

# Slow one client/subscriber to 128 Kbit/s in the policy report.
throttle-client 10.177.124.95 128

# Slow one client/subscriber after 1 MiB of accounted traffic.
quota-client 10.177.124.95 1048576 128

# Slow every client/subscriber after 10 MiB of accounted traffic.
quota-all 10485760 256
```

The hostname match is label-aware: `google.com` matches `www.google.com`, but not `fakegoogle.com`. IP matching is exact because broad IP rules can accidentally block unrelated sites hosted by the same CDN.

## Source map

- `pcap.*`: endian-safe classic/modified PCAP records.
- `ethernet.*`: Ethernet and stacked VLAN decoding.
- `ipv4.*`, `ipv6.*`: network layer bounds and metadata.
- `tcp.*`, `udp.*`: transport headers, flags, and payload spans.
- `flow.*`: canonical flows and bounded out-of-order TCP reassembly.
- `http.*`: plaintext HTTP request line, Host, and User-Agent.
- `tls.*`: TLS handshake records, ClientHello SNI, and ALPN.
- `dns.*`: DNS/mDNS question names over UDP and length-prefixed TCP, including compression pointers.
- `policy.*`: hostname, server-IP, client-IP, and throttling policy decisions.
- `policy_loader.*`: human-readable policy rule file parser.
- `dpi.*`: pipeline orchestration and reporting.
- `enforcer.h`: boundary for a separately authorized live adapter.

## Enforcement boundary

PCAP files are historical data, so this executable cannot drop packets or shape bandwidth. Implement `PacketEnforcer` using an OS-specific live interception layer:

- Windows prototype: WinDivert; production integration: Windows Filtering Platform.
- Linux gateway: nftables/NFQUEUE for blocking and `tc` for shaping.

Keep live enforcement separate from parsers. A `BLOCK` decision should drop/reject the flow, while `THROTTLE` should update a per-subscriber token bucket or OS queue. IP-only website blocking is intentionally avoided because CDNs commonly share addresses.

## Deliberate limits

- No IPv4/IPv6 fragment reassembly; fragments are counted and skipped.
- No TLS decryption or HTTPS path inspection.
- No ECH bypass.
- No QUIC Initial decoder.
- The in-memory inspection window is bounded to 1 MiB and 4096 segments per direction.

These limits should remain explicit rather than silently producing unreliable policy decisions.
