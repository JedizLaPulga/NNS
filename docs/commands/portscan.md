# Port Scan Command

Scan ports on target hosts to discover open services using TCP connect scanning.

## Usage

```bash
nns portscan [OPTIONS] <HOST>
```

**Note**: Flags must come before the host argument.

## Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ports` | string | - | Comma-separated ports or ranges (e.g., `80,443,8000-9000`) |
| `--common` | bool | false | Use common ports preset (21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443) |
| `--timeout` | duration | 2s | Connection timeout per port |
| `--concurrent` | int | 100 | Number of concurrent workers |
| `--help` | bool | false | Show help message |

> **Important**: You must specify either `--ports` or `--common` flag.

## Examples

### Basic Port Scanning

```bash
# Scan specific ports
nns portscan --ports 80,443 example.com

# Scan common ports
nns portscan --common 192.168.1.1

# Scan port ranges
nns portscan --ports 1-1024 scanme.nmap.org

# Mixed ports and ranges
nns portscan --ports 22,80,443,8000-9000 localhost
```

### Advanced Options

```bash
# Custom timeout for slow networks
nns portscan --ports 80,443 --timeout 5s example.com

# Adjust concurrency (lower for slower networks, higher for fast LANs)
nns portscan --ports 1-65535 --concurrent 500 192.168.1.1

# Scan subnet (CIDR notation)
nns portscan --common 192.168.1.0/24
```

## Output

The scanner displays results in a formatted table:

```
Scanning example.com...

PORT       STATE      BANNER
--------------------------------------------
80         open       -
443        open       -

Summary: 2/16 ports open
```

### Output Fields

- **PORT**: Port number
- **STATE**: Port state (`open` or omitted if closed)
- **BANNER**: Service banner if available (first 30 chars)

## Technical Details

### Scanning Method

NNS uses **TCP connect scanning**, which:
- Completes a full TCP three-way handshake
- Is reliable and accurate
- Does not require special privileges (unlike SYN scanning)
- Is slower than SYN scanning but works everywhere
- Leaves connections in server logs

### Concurrency

The scanner uses a worker pool pattern:
- Default: 100 concurrent workers
- Distributes port scanning across goroutines
- Dramatically faster than sequential scanning
- Configurable via `--concurrent` flag

### Performance Tips

1. **Adjust concurrency based on network:**
   - Local network: `--concurrent 500` or higher
   - Remote hosts: `--concurrent 100` (default)
   - Slow networks: `--concurrent 50` or lower

2. **Use appropriate timeouts:**
   - Fast networks: `--timeout 1s`
   - Default: `--timeout 2s`
   - Slow/unreliable: `--timeout 5s` or higher

3. **Scan smart:**
   - Use `--common` for quick checks
   - Scan specific ports rather than full range
   - Scan subnets during off-hours

### Port Range Syntax

- Single port: `80`
- Multiple ports: `80,443,8080`
- Port range: `1-1024`
- Mixed: `22,80,443,8000-9000`
- Spaces allowed: `80, 443, 8080`

### CIDR Support

Target can be:
- Single host: `example.com` or `192.168.1.1`
- Subnet: `192.168.1.0/24` (scans all hosts in subnet)
- Small subnets recommended for responsiveness

## Common Use Cases

### Security Auditing
```bash
# Check web services
nns portscan --ports 80,443,8080,8443 myserver.com

# Full port scan (takes time!)
nns portscan --ports 1-65535 192.168.1.1
```

### Network Discovery
```bash
# Find active services on network
nns portscan --common 192.168.1.0/24
```

### Troubleshooting
```bash
# Check if web server is reachable
nns portscan --ports 80,443 example.com

# Verify database connectivity
nns portscan --ports 3306,5432 db.internal.com
```

## Notes

- Closed ports are not displayed (reduces clutter)
- Banner grabbing attempts to read service response
- Some services don't send banners immediately
- Scanning may trigger IDS/IPS systems
- Always get permission before scanning networks you don't own
