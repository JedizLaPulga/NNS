# nns sweep

Discover live hosts on a network using TCP probes.

## Usage

```bash
nns sweep [CIDR] [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | `1s` | Timeout per host probe |
| `--concurrent` | `-c` | `256` | Number of concurrent workers |
| `--ports` | `-p` | `80,443,22,445,3389` | Ports to check |
| `--resolve` | `-r` | `true` | Resolve hostnames for discovered hosts |
| `--help` | | | Show help message |

## Examples

### Scan a /24 network
```bash
nns sweep 192.168.1.0/24
```

### Scan with custom ports
```bash
nns sweep 10.0.0.0/24 --ports 22,80,443,8080,3306
```

### Fast scan with shorter timeout
```bash
nns sweep 172.16.0.0/24 --timeout 500ms --concurrent 512
```

### Scan without hostname resolution (faster)
```bash
nns sweep 192.168.1.0/24 --resolve=false
```

## Output

```
Sweeping 192.168.1.0/24 (254 hosts)...

IP               PORT     HOSTNAME                       LATENCY
────────────────────────────────────────────────────────────────
192.168.1.1      80       router.local.                  12ms
192.168.1.50     22       server.local.                  8ms
192.168.1.100    443      desktop.local.                 15ms

────────────────────────────────────────────────────────────────
Scan complete: 3/254 hosts alive
```

## How It Works

The sweep command uses TCP connect probes to discover live hosts. For each host in the CIDR range:

1. Attempts TCP connections to the specified ports
2. If any port responds, the host is marked as alive
3. Records the responding port and connection latency
4. Optionally resolves the hostname via reverse DNS

## Performance Tips

- Use `--resolve=false` for faster scans on large networks
- Increase `--concurrent` for larger networks (up to 1000+)
- Use shorter `--timeout` values (250ms-500ms) for local networks
- For remote networks, use longer timeouts (2s-5s)

## Notes

- This command uses TCP connect scanning (not ICMP)
- Does not require administrator/root privileges
- Suitable for network inventory and discovery
