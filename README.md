# NNS - Network Swiss Army Knife

<p align="center">
  <img src="img/nns.png" alt="NNS Logo" width="200"/>
</p>

A powerful networking toolkit for sysadmins and developers, built with Go's standard library and official sub-repositories.

## Features

- **Ping** - Send ICMP echo requests to test network connectivity and measure latency
- **Traceroute** - Trace the network path to a destination host with AS lookup
- **Port Scanning** - Discover open ports and services on target hosts
- **HTTP Benchmarking** - Performance test HTTP endpoints with detailed metrics
- **Debug Proxy** - Local proxy server for debugging HTTP traffic

## Why NNS?

- ✅ **Minimal Dependencies** - Built only with `net`, `http`, and `os` from Go stdlib
- ✅ **Single Binary** - Easy deployment and distribution
- ✅ **Cross-Platform** - Works on Linux, Windows, and macOS
- ✅ **Fast & Lightweight** - No bloat, pure performance
- ✅ **Scriptable** - Perfect for automation and scripting

## Installation

### From Source

```bash
git clone https://github.com/JedizLaPulga/NNS.git
cd NNS
go build -o nns ./cmd/nns
```

### Binary Releases
*Coming soon!*

## Quick Start

```bash
# Show available commands
nns --help

# Check version
nns --version

# Ping a host
nns ping google.com

# Scan ports
nns portscan 192.168.1.1 --ports 80,443

# Benchmark an API
nns bench https://api.example.com --requests 1000

# Trace route to host
nns traceroute google.com

# Start debugging proxy (Coming Soon)
nns proxy --port 8080
```

## Documentation

See the [docs](docs/) directory for detailed documentation on each command:

- [Ping](docs/commands/ping.md)
- [Traceroute](docs/commands/traceroute.md)
- [Port Scan](docs/commands/portscan.md)
- [HTTP Benchmark](docs/commands/bench.md)
- [Proxy Server](docs/commands/proxy.md)

## Project Structure

```
NNS/
├── cmd/nns/           # Main application entry point
├── internal/          # Private packages
│   ├── cli/          # CLI utilities
│   ├── ping/         # Ping implementation
│   ├── traceroute/   # Traceroute implementation
│   ├── portscan/     # Port scanning
│   ├── bench/        # HTTP benchmarking
│   └── proxy/        # Proxy server
├── docs/             # Documentation
└── img/              # Assets and logo
```

## Development

Built with Go programming language, following best practices and extensive testing.

### Building

```bash
go build -o nns ./cmd/nns
```

### Running Tests

```bash
go test ./...
```

## Contributing

Contributions are welcome! Please ensure:
1. All code is extensively tested
2. Follow Go best practices
3. Use only the Go standard library (or `golang.org/x/*` if absolutely necessary)

## License

See [LICENSE](LICENSE) for details.

## Author

Built by JedizLaPulga
