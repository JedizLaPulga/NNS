# NNS - Network Swiss Army Knife

<p align="center">
  <img src="img/nns.png" alt="NNS Logo" width="200"/>
</p>

A powerful networking toolkit for sysadmins and developers, built with Go's standard library and official sub-repositories.

## Features

### Network Diagnostics
- **Ping** - Send ICMP echo requests with advanced statistics (jitter, percentiles)
- **Traceroute** - Trace the network path to a destination host with AS lookup
- **MTR** - My TraceRoute - continuous ping + traceroute combined
- **TCP Test** - TCP connectivity test with DNS/connect/TLS timing breakdown

### Discovery & Scanning
- **Port Scan** - Discover open ports on target hosts
- **Services** - Detect services via banner grabbing and protocol identification
- **Network Sweep** - Discover live hosts on a network (CIDR range scanning)
- **ARP Table** - View ARP cache with MAC vendor lookup

### Performance & Monitoring
- **HTTP Benchmark** - Performance test HTTP endpoints with detailed metrics
- **Speed Test** - Internet bandwidth speed test
- **Bandwidth Monitor** - Real-time bandwidth usage per interface
- **Latency Monitor** - Continuous latency monitoring with sparkline visualization

### DNS & Domain
- **DNS Lookup** - Query DNS records (A, MX, TXT, NS, etc.) with custom resolvers
- **DNS Trace** - Trace DNS resolution chain from root servers
- **WHOIS Lookup** - Query domain and IP registration information
- **IP Info** - IP geolocation and ASN lookup

### Security & Certificates
- **SSL Analysis** - Analyze TLS certificates with security grading (A+ to F)
- **HTTP Headers** - Analyze HTTP security headers

### Utilities
- **HTTP Client** - HTTP client with detailed timing breakdown (DNS, TLS, TTFB)
- **Debug Proxy** - Local proxy server for debugging HTTP traffic
- **Netstat** - Show network connections and routing tables
- **Wake-on-LAN** - Power on remote machines via WoL magic packets
- **CIDR Calculator** - Subnet calculator and IP range utilities
- **MAC Lookup** - MAC address vendor lookup
- **Interfaces** - List network interfaces with details
- **Net Watch** - Monitor network changes in real-time
- **Port Forward** - TCP port forwarding / tunnel utility
- **Connectivity Test** - Test connectivity to multiple hosts in parallel
- **Listen** - TCP/UDP listener for connectivity testing (like netcat)
- **URL Check** - Check health of multiple URLs with status codes

## Why NNS?

- ✅ **30 Commands** - Comprehensive networking toolkit
- ✅ **Minimal Dependencies** - Built only with Go stdlib and `golang.org/x/*`
- ✅ **Single Binary** - Easy deployment and distribution
- ✅ **Cross-Platform** - Works on Linux, Windows, and macOS
- ✅ **Fast & Lightweight** - No bloat, pure performance
- ✅ **Scriptable** - Perfect for automation and scripting
- ✅ **CI/CD Ready** - GitHub Actions workflows included

## Installation

### From Source

```bash
git clone https://github.com/JedizLaPulga/NNS.git
cd NNS
go build -o nns ./cmd/nns
```

### With Version Info

```bash
go build -ldflags="-X main.version=v1.0.0 -X main.commit=$(git rev-parse --short HEAD)" -o nns ./cmd/nns
```

### Binary Releases

Download from [Releases](https://github.com/JedizLaPulga/NNS/releases) page.

## Quick Start

```bash
# Show available commands
nns --help

# Check version
nns --version

# === Network Diagnostics ===
nns ping google.com -c 5
nns traceroute google.com
nns mtr google.com --count 10
nns tcptest google.com -p 443 -c 4

# === Discovery & Scanning ===
nns portscan 192.168.1.1 --ports 22,80,443
nns services scanme.nmap.org -p 22,80,443 --open
nns sweep 192.168.1.0/24
nns arp

# === Performance & Monitoring ===
nns bench https://api.example.com --requests 1000
nns speedtest
nns bwmon --simulate

# === DNS & Domain ===
nns dns google.com --type MX
nns whois google.com
nns ipinfo 8.8.8.8

# === Security ===
nns ssl google.com --chain
nns headers https://example.com

# === Utilities ===
nns http https://api.example.com --timing
nns proxy --port 8080
nns netstat --listen
nns wol AA:BB:CC:DD:EE:FF
nns cidr 192.168.1.0/24
nns mac AA:BB:CC:DD:EE:FF
nns interfaces --active
nns netwatch
```

## Command Reference

| Command | Description |
|---------|-------------|
| `ping` | ICMP echo requests with advanced statistics |
| `traceroute` | Trace network path to host |
| `mtr` | Continuous ping + traceroute |
| `tcptest` | TCP connectivity with timing breakdown |
| `portscan` | Port scanning |
| `services` | Service detection via banner grabbing |
| `sweep` | Network host discovery |
| `arp` | ARP table with vendor lookup |
| `bench` | HTTP endpoint benchmarking |
| `speedtest` | Bandwidth speed test |
| `bwmon` | Real-time bandwidth monitor |
| `dns` | DNS record lookups |
| `whois` | Domain/IP registration info |
| `ipinfo` | IP geolocation and ASN |
| `ssl` | TLS certificate analysis |
| `headers` | HTTP security headers |
| `http` | HTTP client with timing |
| `proxy` | Debug proxy server |
| `netstat` | Network connections |
| `wol` | Wake-on-LAN |
| `cidr` | Subnet calculator |
| `mac` | MAC vendor lookup |
| `interfaces` | List network interfaces |
| `netwatch` | Monitor network changes |
| `latency` | Continuous latency monitoring with sparkline |
| `forward` | TCP port forwarding / tunnel |
| `conntest` | Test connectivity to multiple hosts |
| `dnstrace` | Trace DNS resolution chain from root servers |
| `listen` | TCP/UDP listener for connectivity testing |
| `urlcheck` | Check health of multiple URLs |

## Project Structure

```
NNS/
├── cmd/nns/           # CLI entry point (31 files)
│   ├── main.go        # Command router
│   └── cmd_*.go       # Individual command handlers
├── internal/          # Private packages (27 packages)
│   ├── ping/          # ICMP ping
│   ├── traceroute/    # Traceroute
│   ├── mtr/           # My TraceRoute
│   ├── tcptest/       # TCP testing
│   ├── portscan/      # Port scanning
│   ├── services/      # Service detection
│   ├── sweep/         # Network sweep
│   ├── arp/           # ARP table
│   ├── bench/         # HTTP benchmark
│   ├── speedtest/     # Speed test
│   ├── bwmon/         # Bandwidth monitor
│   ├── dns/           # DNS lookups
│   ├── whois/         # WHOIS client
│   ├── ipinfo/        # IP geolocation
│   ├── ssl/           # SSL analysis
│   ├── headers/       # HTTP headers
│   ├── httpclient/    # HTTP client
│   ├── proxy/         # Proxy server
│   ├── netstat/       # Network stats
│   ├── wol/           # Wake-on-LAN
│   ├── cidr/          # CIDR calculator
│   ├── macutil/       # MAC utilities
│   ├── interfaces/    # Network interfaces
│   ├── netwatch/      # Network monitor
│   └── ...
├── .github/workflows/ # CI/CD pipelines
├── docs/              # Documentation
└── img/               # Assets
```

## Development

### Building

```bash
go build -o nns ./cmd/nns
```

### Running Tests

```bash
go test ./...
```

### Linting

```bash
golangci-lint run
```

## CI/CD

This project includes GitHub Actions workflows:

- **CI** (`ci.yml`) - Runs on every push/PR
  - Tests on Linux, Windows, macOS
  - Tests with Go 1.22 and 1.23
  - Runs golangci-lint
  - Cross-compiles for 5 platforms

- **Release** (`release.yml`) - Runs on version tags
  - Builds binaries for all platforms
  - Creates GitHub Release with checksums

## Contributing

Contributions are welcome! Please ensure:
1. All code is extensively tested
2. Follow Go best practices
3. Use only the Go standard library (or `golang.org/x/*` if absolutely necessary)
4. Run `golangci-lint` before submitting

## License

See [LICENSE](LICENSE) for details.

## Author

Built by JedizLaPulga
