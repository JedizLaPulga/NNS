# Ping Command

Send ICMP Echo Requests to network hosts to measure reachability, latency, and packet loss. NNS Ping provides enhanced statistics including jitter, percentiles, and quality ratings.

## Usage

```bash
nns ping [OPTIONS] <HOST>
```

> **Note**: Ping requires administrator/root privileges to open raw sockets for ICMP.

## Options

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--count` | `-c` | int | 0 | Number of pings to send (0 = infinite) |
| `--interval` | `-i` | duration | 1s | Time between pings |
| `--timeout` | `-t` | duration | 4s | Timeout per ping request |
| `--size` | `-s` | int | 64 | Packet size in bytes |
| `--help` | - | bool | false | Show help message |

## Examples

### Basic Usage

```bash
# Ping indefinitely (Ctrl+C to stop)
nns ping google.com


## Technical Details

*To be documented when implemented*
