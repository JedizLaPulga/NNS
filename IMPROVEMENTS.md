# NNS Project Improvements Summary

**Session Date:** 2026-01-21

---

## 1. ✅ Refactored Monolithic main.go

| Before | After |
|--------|-------|
| 1 file, 2,363 lines | 22 files |
| All code in `main.go` | `main.go` (112 lines) + 21 `cmd_*.go` files |

**Files Created:**
```
cmd/nns/
├── main.go           # Router + help only
├── cmd_ping.go
├── cmd_traceroute.go
├── cmd_portscan.go
├── cmd_bench.go
├── cmd_dns.go
├── cmd_ssl.go
├── cmd_http.go
├── cmd_proxy.go
├── cmd_sweep.go
├── cmd_arp.go
├── cmd_whois.go
├── cmd_netstat.go
├── cmd_wol.go
├── cmd_headers.go
├── cmd_ipinfo.go
├── cmd_cidr.go
├── cmd_mac.go
├── cmd_mtr.go
├── cmd_interfaces.go
├── cmd_speedtest.go
└── cmd_netwatch.go
```

---

## 2. ✅ Added CI/CD Pipeline

**Files Created:**

| File | Purpose |
|------|---------|
| `.github/workflows/ci.yml` | Automated testing on every push/PR |
| `.github/workflows/release.yml` | Auto-builds releases on version tags |
| `.golangci.yml` | Linter configuration |

**CI Features:**
- Tests on **3 OS**: Ubuntu, Windows, macOS
- Tests with **2 Go versions**: 1.22, 1.23
- **golangci-lint** for code quality
- **Cross-compilation** for 5 platforms (Linux, macOS, Windows × amd64/arm64)
- **Artifact uploads** for built binaries

**Release Features:**
- Triggered by `git tag v*`
- Builds binaries for all platforms
- Creates GitHub Release with checksums
- Auto-detects prereleases (alpha/beta/rc)

---

## 3. ✅ Added Version Injection

**Changed `main.go`:**
```go
// Before
const version = "0.1.0"

// After
var (
    version = "dev"
    commit  = "none"
    date    = "unknown"
)
```

**Enhanced `--version` output:**
```
nns version v1.0.0
  commit:  abc1234
  built:   2026-01-21
  go:      go1.25.5
  os/arch: windows/amd64
```

**Build command:**
```bash
go build -ldflags="-X main.version=v1.0.0 -X main.commit=$(git rev-parse --short HEAD)" ./cmd/nns
```

---

## 4. ✅ Created Project Documentation

**File:** `project_rules.md` (in `.gitignore` for privacy)

Contains:
- Project architecture overview
- Code quality assessment
- Test status for all 24 packages
- Coding conventions
- Recommended improvements
- Build & run commands

---

## Summary

| Metric | Before | After |
|--------|--------|-------|
| Main file lines | 2,363 | 112 |
| Command files | 1 | 22 |
| CI/CD workflows | 0 | 2 |
| Version injection | ❌ | ✅ |
| Linter config | ❌ | ✅ |
| Build info in `--version` | ❌ | ✅ |

---

## 5. ✅ Added New Commands (2026-01-22)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns tcptest` | TCP connectivity test with DNS/connect/TLS timing breakdown | 7 |
| `nns bwmon` | Real-time bandwidth monitor per interface | 9 |
| `nns services` | Service detection / banner grabbing for ports | 12 |

**Total commands:** 24

**Files Created:**
```
internal/tcptest/tcptest.go         # TCP test library
internal/tcptest/tcptest_test.go    # Tests
internal/bwmon/bwmon.go             # Bandwidth monitor library
internal/bwmon/bwmon_test.go        # Tests
internal/services/services.go       # Service detection library
internal/services/services_test.go  # Tests
cmd/nns/cmd_tcptest.go              # CLI handler
cmd/nns/cmd_bwmon.go                # CLI handler
cmd/nns/cmd_services.go             # CLI handler
```

---

## 6. ✅ Added New Commands (2026-01-23)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns latency` | Continuous latency monitoring with sparkline visualization and alerting | 10 |
| `nns forward` | TCP port forwarding / tunnel utility | 9 |
| `nns conntest` | Parallel connectivity testing for multiple hosts | 11 |

**Total commands:** 27

**Files Created:**
```
internal/latency/latency.go          # Latency monitor library
internal/latency/latency_test.go     # Tests
internal/portforward/portforward.go  # Port forwarding library
internal/portforward/portforward_test.go  # Tests
internal/conntest/conntest.go        # Connection testing library
internal/conntest/conntest_test.go   # Tests
cmd/nns/cmd_latency.go               # CLI handler
cmd/nns/cmd_forward.go               # CLI handler
cmd/nns/cmd_conntest.go              # CLI handler
```

**New Features:**
- **Latency Monitor**: Real-time latency tracking with sparkline graphs, percentile stats (p50/p95/p99), jitter calculation, and configurable alert thresholds
- **Port Forward**: TCP tunnel with connection tracking, bandwidth statistics, and event callbacks
- **Connectivity Tester**: Parallel testing of multiple hosts with TCP/TLS support, sorting, and summary statistics

---

## 7. ✅ Added New Commands (2026-01-24)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns dnstrace` | DNS resolution chain tracing from root servers | 10 |
| `nns listen` | TCP/UDP listener for connectivity testing (netcat-like) | 12 |
| `nns urlcheck` | URL health checker with status codes and response times | 10 |

**Total commands:** 30

**Files Created:**
```
internal/dnstrace/dnstrace.go           # DNS trace library
internal/dnstrace/dnstrace_test.go      # Tests
internal/listen/listen.go               # TCP/UDP listener library
internal/listen/listen_test.go          # Tests
internal/urlcheck/urlcheck.go           # URL health checker library
internal/urlcheck/urlcheck_test.go      # Tests
cmd/nns/cmd_dnstrace.go                 # CLI handler
cmd/nns/cmd_listen.go                   # CLI handler
cmd/nns/cmd_urlcheck.go                 # CLI handler
```

**New Features:**
- **DNS Trace**: Follow DNS resolution from root servers through TLD to authoritative servers
- **Listen**: Netcat-like listener with echo mode, connection tracking, and statistics
- **URL Check**: Parallel URL health monitoring with status codes, TLS info, and response times

---

## 8. ✅ Added New Commands (2026-01-28)

**Files Created:**
```
internal/pcap/pcap.go                   # Packet capture library
internal/pcap/pcap_test.go              # Tests
internal/netpath/netpath.go             # Network path analyzer
internal/netpath/netpath_test.go        # Tests
internal/httpstress/httpstress.go       # HTTP stress testing
internal/httpstress/httpstress_test.go  # Tests
internal/sshscan/sshscan.go             # SSH scanner library
internal/sshscan/sshscan_test.go        # Tests
internal/dnsperf/dnsperf.go             # DNS benchmark library
internal/dnsperf/dnsperf_test.go        # Tests
cmd/nns/cmd_pcap.go                     # CLI handler
cmd/nns/cmd_netpath.go                  # CLI handler
cmd/nns/cmd_httpstress.go               # CLI handler
cmd/nns/cmd_sshscan.go                  # CLI handler
cmd/nns/cmd_dnsperf.go                  # CLI handler
```

**New Features:**
- **Packet Capture**: Network packet capture with protocol/port/host filtering and statistics
- **Network Path Analysis**: Full path tracing with quality scores, jitter, and packet loss per hop
- **HTTP Stress Test**: Load testing with concurrency, percentile latencies (P50/P90/P99), and progress
- **SSH Security Scan**: Server fingerprinting, algorithm detection, and vulnerability assessment
- **DNS Performance**: Benchmark multiple resolvers (Google, Cloudflare, Quad9, etc.) with comparison
---

## 9. ✅ Added New Commands (2026-01-29)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns websocket` | WebSocket connectivity and latency tester | 11 |
| `nns tlscheck` | TLS certificate chain validator with expiry warnings | 10 |
| `nns routes` | System routing table viewer with gateway analysis | 11 |

**Total commands:** 38

**Files Created:**
```
internal/websocket/websocket.go         # WebSocket test library
internal/websocket/websocket_test.go    # Tests
internal/tlscheck/tlscheck.go           # TLS checker library
internal/tlscheck/tlscheck_test.go      # Tests
internal/routes/routes.go               # Routes library
internal/routes/routes_test.go          # Tests
cmd/nns/cmd_websocket.go                # CLI handler
cmd/nns/cmd_tlscheck.go                 # CLI handler
cmd/nns/cmd_routes.go                   # CLI handler
```

**New Features:**
- **WebSocket Test**: WebSocket connectivity with RTT measurement, ping-pong latency, jitter, and statistics
- **TLS Check**: Certificate chain validation with expiry warnings, security grading (A+ to F), and cipher analysis
- **Routes**: Cross-platform routing table display with filtering, gateway testing, and interface analysis

---

## Remaining (Optional)

| Task | Priority |
|------|----------|
| Fix flaky speedtest | 🟡 Medium |
| Add WoL tests | 🟢 Low |

---

## 10. ✅ Added New Commands (2026-02-01)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns geoloc` | IP geolocation with city, country, ASN, and coordinates | 10 |
| `nns subnet` | Subnet calculator with split, merge, contains, overlap checks | 10 |
| `nns wakewait` | Wake-on-LAN with active polling until host comes online | 7 |

**Total commands:** 41

**Files Created:**
```
internal/geoloc/geoloc.go             # IP geolocation library
internal/geoloc/geoloc_test.go        # Tests
internal/subnet/subnet.go             # Subnet calculator library
internal/subnet/subnet_test.go        # Tests
internal/wakewait/wakewait.go         # Wake-wait library
internal/wakewait/wakewait_test.go    # Tests
cmd/nns/cmd_geoloc.go                 # CLI handler
cmd/nns/cmd_subnet.go                 # CLI handler
cmd/nns/cmd_wakewait.go               # CLI handler
```

**New Features:**
- **IP Geolocation**: Lookup IPs to get city, country, ASN, ISP, coordinates with batch support and caching
- **Subnet Calculator**: Calculate network/broadcast, split into smaller subnets, check containment/overlap, list hosts
- **Wake-and-Wait**: Send WoL packet and actively monitor until host comes online with configurable port/timeout/retries

---

## 11. ✅ Added New Commands (2026-02-02)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns dnssec` | DNSSEC chain-of-trust validation with security grading | 14 |
| `nns blacklist` | IP/domain reputation check against 13+ RBLs/DNSBLs | 12 |
| `nns fingerprint` | TCP/IP stack OS fingerprinting and service detection | 14 |

**Total commands:** 44

**Files Created:**
```
internal/dnssec/dnssec.go             # DNSSEC validation library
internal/dnssec/dnssec_test.go        # Tests
internal/blacklist/blacklist.go       # Blacklist checker library
internal/blacklist/blacklist_test.go  # Tests
internal/fingerprint/fingerprint.go   # OS/service fingerprinting
internal/fingerprint/fingerprint_test.go # Tests
cmd/nns/cmd_dnssec.go                 # CLI handler
cmd/nns/cmd_blacklist.go              # CLI handler
cmd/nns/cmd_fingerprint.go            # CLI handler
```

**New Features:**
- **DNSSEC Validation**: Verify chain of trust from root, detect weak algorithms (RSA/MD5, SHA-1), check signature expiry, security grading (A+ to F)
- **Blacklist Checker**: Query 13+ spam/malware blacklists (Spamhaus, SpamCop, Barracuda, SORBS, etc.), aggregate risk scoring, TXT reason lookup
- **OS Fingerprinting**: TCP/IP stack analysis to identify OS family (Linux/Windows/BSD/macOS), service banner grabbing, version detection

---

## 12. ✅ Added New Commands (2026-02-03)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns snmp` | SNMP device discovery and OID walking with security audit | 14 |
| `nns resolvers` | Compare DNS resolvers for speed, privacy, and security | 8 |
| `nns ntp` | NTP server checker with time offset analysis | 10 |
| `nns upnp` | UPnP device discovery with service enumeration | 9 |
| `nns leak` | DNS/IP leak testing for VPN privacy audit | 11 |
| `nns netspeed` | Internal network speed test (iperf-like client/server) | 12 |

**Total commands:** 50

**Files Created:**
```
internal/snmp/snmp.go                 # SNMP scanner library
internal/snmp/snmp_test.go            # Tests
internal/resolvers/resolvers.go       # DNS resolver comparison
internal/resolvers/resolvers_test.go  # Tests
internal/ntp/ntp.go                   # NTP checker library
internal/ntp/ntp_test.go              # Tests
internal/upnp/upnp.go                 # UPnP discovery library
internal/upnp/upnp_test.go            # Tests
internal/leak/leak.go                 # Leak tester library
internal/leak/leak_test.go            # Tests
internal/netspeed/netspeed.go         # Speed test library
internal/netspeed/netspeed_test.go    # Tests
cmd/nns/cmd_snmp.go                   # CLI handler
cmd/nns/cmd_resolvers.go              # CLI handler
cmd/nns/cmd_ntp.go                    # CLI handler
cmd/nns/cmd_upnp.go                   # CLI handler
cmd/nns/cmd_leak.go                   # CLI handler
cmd/nns/cmd_netspeed.go               # CLI handler
```

**New Features:**
- **SNMP Scanner**: Device discovery, OID walking, community string security audit, risk assessment
- **DNS Resolver Comparison**: Test Google, Cloudflare, Quad9, etc. for latency, reliability, privacy
- **NTP Checker**: Query NTP servers, analyze time offset, detect clock drift, stratum info
- **UPnP Discovery**: Find IoT devices, routers, media servers with service enumeration
- **Leak Tester**: DNS leak detection, public IP analysis, VPN validation, privacy recommendations
- **Network Speed Test**: iperf-like client/server for LAN bandwidth testing, bidirectional support

---

## 13. ✅ Added New Commands (2026-02-11)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns mqtt` | MQTT broker connectivity, auth testing, topic probing, and latency | 19 |
| `nns netaudit` | Network security audit — open DNS, SNMP defaults, weak TLS, exposed services | 24 |
| `nns pcping` | Protocol-aware ping via TCP/UDP/HTTP/DNS (when ICMP is blocked) | 18 |

**Total commands:** 53

**Files Created:**
```
internal/mqtt/mqtt.go                 # MQTT broker checker library
internal/mqtt/mqtt_test.go            # Tests
internal/netaudit/netaudit.go         # Network security audit library
internal/netaudit/netaudit_test.go    # Tests
internal/pcping/pcping.go             # Protocol-aware ping library
internal/pcping/pcping_test.go        # Tests
cmd/nns/cmd_mqtt.go                   # CLI handler
cmd/nns/cmd_netaudit.go               # CLI handler
cmd/nns/cmd_pcping.go                 # CLI handler
```

**New Features:**
- **MQTT Checker**: Test broker connectivity, anonymous auth detection, PINGREQ/PINGRESP latency, topic subscription probing, security assessment ($SYS exposure, wildcard access, TLS)
- **Network Audit**: Scan for open DNS resolvers (DDoS risk), SNMP default community strings, Telnet exposure, weak TLS, expired certs, banner leakage, dangerous open ports — graded A-F
- **Protocol Ping**: TCP connect, UDP, HTTP GET, and DNS query probes with RTT statistics (min/avg/max/median/p95/p99/stddev), quality assessment, and loss tracking

---

## 14. ✅ Added New Commands (2026-02-12)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns fwd` | HTTP/HTTPS reverse proxy with request logging, header injection, and latency stats | 13 |
| `nns certhunt` | Certificate transparency log search via crt.sh with live cert comparison | 17 |
| `nns neighbors` | mDNS/DNS-SD network neighbor discovery (Bonjour) | 20 |

**Total commands:** 56

**Files Created:**
```
internal/reverseproxy/reverseproxy.go         # Reverse proxy library
internal/reverseproxy/reverseproxy_test.go    # Tests
internal/certhunt/certhunt.go                 # CT log search library
internal/certhunt/certhunt_test.go            # Tests
internal/neighbors/neighbors.go              # mDNS/DNS-SD discovery library
internal/neighbors/neighbors_test.go         # Tests
cmd/nns/cmd_fwd.go                           # CLI handler
cmd/nns/cmd_certhunt.go                      # CLI handler
cmd/nns/cmd_neighbors.go                     # CLI handler
```

**New Features:**
- **Reverse Proxy**: Full HTTP/HTTPS reverse proxy with per-request logging, header injection/stripping, latency percentiles (P50/P95/P99), status code tracking, and throughput stats
- **Certificate Hunt**: Search crt.sh Certificate Transparency logs for all issued certificates, deduplicate, detect wildcards/expired certs, compare with live TLS certificate, security grading
- **Neighbor Discovery**: mDNS multicast queries for 13+ service types (HTTP, SSH, SMB, Printer, AirPlay, Chromecast, HomeKit, etc.), DNS-SD service browsing, TXT metadata extraction

---

## 15. ✅ Added New Commands (2026-02-13)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns asn` | BGP/ASN lookup via Team Cymru DNS and RDAP | 13 |
| `nns portknock` | TCP/UDP port knock sequence sender with verification | 16 |
| `nns jwt` | JWT token decoder and security analyzer (grade A-F) | 20 |

**Total commands:** 59

**Files Created:**
```
internal/asn/asn.go                     # ASN lookup library
internal/asn/asn_test.go                # Tests
internal/portknock/portknock.go         # Port knock library
internal/portknock/portknock_test.go    # Tests
internal/jwtutil/jwtutil.go            # JWT decoder library
internal/jwtutil/jwtutil_test.go       # Tests
cmd/nns/cmd_asn.go                     # CLI handler
cmd/nns/cmd_portknock.go               # CLI handler
cmd/nns/cmd_jwt.go                     # CLI handler
```

**New Features:**
- **ASN Lookup**: Team Cymru DNS-based ASN resolution, RDAP org details, IPv4/IPv6 support, batch lookup, prefix/country/registry info
- **Port Knock**: Send TCP/UDP knock sequences to trigger firewall rules, configurable delay/timeout, post-knock port verification, connection state tracking
- **JWT Analyzer**: Decode JWT header and claims, detect `alg=none` and weak algorithms, check expiry/sensitive data in claims, security grading (A-F), stdin support

---

## 16. ✅ Added New Commands (2026-02-14)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns encdec` | Encode/decode utility for Base64, Hex, URL encoding, and Binary | 30 |
| `nns httptrace` | HTTP request tracing with redirect chain, per-hop timing, and security header inspection | 15 |
| `nns cidrmerge` | CIDR aggregation — merge, deduplicate, exclude, containment, and overlap checks | 23 |

**Total commands:** 62

**Files Created:**
```
internal/encdec/encdec.go               # Encode/decode library
internal/encdec/encdec_test.go           # Tests
internal/httptrace/httptrace.go          # HTTP trace library
internal/httptrace/httptrace_test.go     # Tests
internal/cidrmerge/cidrmerge.go          # CIDR merge library
internal/cidrmerge/cidrmerge_test.go     # Tests
cmd/nns/cmd_encdec.go                   # CLI handler
cmd/nns/cmd_httptrace.go                # CLI handler
cmd/nns/cmd_cidrmerge.go                # CLI handler
```

**New Features:**
- **Encode/Decode**: Base64, Base64URL, Hex, URL encoding, and Binary representations with encode, decode, auto-detection, and encode-all modes. Supports stdin input.
- **HTTP Trace**: Follow HTTP redirect chains with full timing breakdown per hop (DNS, connect, TLS handshake, TTFB). Detects security headers (HSTS, CSP, X-Frame-Options). Custom method and headers support.
- **CIDR Merge**: Consolidate overlapping and adjacent IP prefixes into minimal set. Contains, overlap, and exclude operations. Host counting with IPv4/IPv6 support. Handles bare IPs and invalid input gracefully.

---

## 17. ✅ Added New Commands (2026-02-15)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns hashcheck` | Cryptographic hash calculator (MD5, SHA-1, SHA-256, SHA-512) with file hashing and verify mode | 25 |
| `nns netcalc` | Network/IP calculator with subnet info, IP arithmetic, range listing, and binary representation | 22 |
| `nns passwd` | Password strength analyzer with entropy/crack-time estimation and secure password generator | 25 |

**Total commands:** 65

**Files Created:**
```
internal/hashcheck/hashcheck.go         # Hash calculator library
internal/hashcheck/hashcheck_test.go    # Tests
internal/netcalc/netcalc.go             # Network calculator library
internal/netcalc/netcalc_test.go        # Tests
internal/passwd/passwd.go               # Password analyzer/generator library
internal/passwd/passwd_test.go          # Tests
cmd/nns/cmd_hashcheck.go               # CLI handler
cmd/nns/cmd_netcalc.go                 # CLI handler
cmd/nns/cmd_passwd.go                  # CLI handler
```

**New Features:**
- **Hash Check**: Compute MD5, SHA-1, SHA-256, SHA-512 hashes for strings or files. Compare against expected hash for integrity verification. Hash-all mode computes every algorithm at once.
- **Net Calc**: Full subnet breakdown (network/broadcast/wildcard/netmask, host counts, first/last usable). IP arithmetic (add/subtract offset). IP range enumeration. Binary representation. IPv4 class and private range detection.
- **Password**: Entropy-based strength analysis with crack time estimation (10B guesses/sec). Detects common words, repeated chars, sequential patterns. Score 0-100. Cryptographically secure password generator with charset control and exclusion lists.

---

## 18. ✅ Added New Commands (2026-02-16)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns ratelimit` | HTTP rate limit detection — probes endpoints for X-RateLimit headers, 429 responses, and Retry-After policies | 24 |
| `nns ipconv` | IP address format converter — decimal, hex, octal, binary, integer, and IPv6-mapped representations | 28 |
| `nns tcpdump` | TCP connection analyzer — handshake timing, TLS negotiation details, multi-port probing | 17 |

**Total commands:** 68

**Files Created:**
```
internal/ratelimit/ratelimit.go          # Rate limit probe library
internal/ratelimit/ratelimit_test.go     # Tests
internal/ipconv/ipconv.go               # IP converter library
internal/ipconv/ipconv_test.go           # Tests
internal/tcpdump/tcpdump.go             # TCP analyzer library
internal/tcpdump/tcpdump_test.go        # Tests
cmd/nns/cmd_ratelimit.go                # CLI handler
cmd/nns/cmd_ipconv.go                   # CLI handler
cmd/nns/cmd_tcpdump.go                  # CLI handler
```

**New Features:**
- **Rate Limit Probe**: Send configurable burst of requests to discover rate limiting policies. Parses X-RateLimit-Limit/Remaining/Reset/Window headers, detects 429 responses with Retry-After, supports concurrent probing, custom headers, and per-request detail view.
- **IP Converter**: Convert IPs between dotted decimal, hex dotted (0xC0.0xA8.0x01.0x01), hex integer (0xC0A80101), octal (0300.0250.0001.0001), binary, and plain integer. Supports IPv4/IPv6, reverse DNS format, and IPv6-mapped addresses. Flexible input parsing accepts any format.
- **TCP Dump**: Analyze TCP connections with DNS resolution timing, TCP handshake timing, and optional TLS handshake inspection (version, cipher suite, ALPN, server name). Multi-port probing with summary table. Detects IPv4/IPv6 and connection state.

---

## 19. ✅ Added New Commands (2026-02-17)

| Command | Description | Tests |
|---------|-------------|-------|
| `nns sysinfo` | System and network environment info — hostname, OS, CPUs, interfaces, local/public IPs | 14 |
| `nns httphealth` | HTTP endpoint health monitor with continuous polling, uptime tracking, and latency stats | 20 |
| `nns dnsenum` | DNS subdomain enumeration via built-in wordlist, zone transfer attempts, and reverse DNS | 16 |

**Total commands:** 71

**Files Created:**
```
internal/sysinfo/sysinfo.go              # System info library
internal/sysinfo/sysinfo_test.go          # Tests
internal/httphealth/httphealth.go          # HTTP health monitor library
internal/httphealth/httphealth_test.go     # Tests
internal/dnsenum/dnsenum.go               # DNS enumeration library
internal/dnsenum/dnsenum_test.go           # Tests
cmd/nns/cmd_sysinfo.go                    # CLI handler
cmd/nns/cmd_httphealth.go                 # CLI handler
cmd/nns/cmd_dnsenum.go                    # CLI handler
```

**New Features:**
- **System Info**: Collect hostname, OS/arch, Go version, CPU count, all network interfaces with MAC/MTU/flags/addresses, non-loopback local IPs, and optional public IP resolution via OpenDNS. Active-only filter for interfaces.
- **HTTP Health**: Continuous HTTP endpoint health monitoring with configurable interval, custom expected status code, parallel multi-URL checks, uptime percentage calculation, min/avg/max latency tracking, history buffer, and Ctrl+C summary display.
- **DNS Enum**: Subdomain discovery using a 70+ entry built-in wordlist with concurrent DNS lookups, zone transfer (AXFR) attempts against authoritative nameservers, CNAME detection, custom resolver support, and formatted results with IP/CNAME columns.
