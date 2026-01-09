# NNS Documentation

Welcome to the NNS (Network Swiss Army Knife) documentation.

## Quick Start

```bash
# Build the tool
go build -o nns ./cmd/nns

# Show help
./nns --help

# Show version
./nns --version
```

## Commands

NNS provides the following networking tools:

### [Ping](commands/ping.md)
Send ICMP echo requests to test network connectivity and measure latency.

### [Traceroute](commands/traceroute.md)
Trace the network path to a destination host.

### [Port Scan](commands/portscan.md)
Scan ports on target hosts to discover open services.

### [HTTP Benchmark](commands/bench.md)
Benchmark HTTP endpoints for performance testing.

### [Proxy Server](commands/proxy.md)
Start a local HTTP proxy server for debugging network traffic.

## Usage Examples

```bash
# Ping a host
nns ping google.com

# Traceroute to a host
nns traceroute google.com

# Scan common ports
nns portscan 192.168.1.1 --ports 80,443,8080

# Benchmark an API endpoint
nns bench https://api.example.com --requests 1000

# Start a debugging proxy
nns proxy --port 8080
```

## Installation

### From Source

```bash
git clone https://github.com/JedizLaPulga/NNS.git
cd NNS
go build -o nns ./cmd/nns
```

### Binary Release
Coming soon!

## Contributing

Contributions are welcome! Please ensure:
1. All code is extensively tested
2. Follow Go best practices
3. Use only the Go standard library (or golang.org/x/* if necessary)

## License

See [LICENSE](../LICENSE) for details.
