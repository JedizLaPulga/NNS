# nns netstat

Show network connections and routing information.

## Usage

```bash
nns netstat [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--tcp` | `-t` | `false` | Show TCP connections only |
| `--udp` | `-u` | `false` | Show UDP connections only |
| `--listen` | `-l` | `false` | Show listening ports only |
| `--all` | `-a` | `false` | Show all connections |
| `--pid` | `-p` | `false` | Show process IDs (requires admin) |
| `--routing` | `-r` | `false` | Show routing table |
| `--help` | | | Show help message |

## Examples

### Show all active connections
```bash
nns netstat
```

### Show listening ports only
```bash
nns netstat --listen
nns netstat -l
```

### Show TCP connections with PIDs
```bash
nns netstat --tcp --pid
nns netstat -tp
```

### Show UDP connections
```bash
nns netstat --udp
nns netstat -u
```

### Show routing table
```bash
nns netstat --routing
nns netstat -r
```

## Output

### Connections
```
PROTO    LOCAL                     REMOTE                    STATE
────────────────────────────────────────────────────────────────────────────────
tcp      0.0.0.0:22                *:*                       LISTEN
tcp      0.0.0.0:80                *:*                       LISTEN
tcp      192.168.1.100:52341       93.184.216.34:443         ESTABLISHED
tcp      192.168.1.100:52342       172.217.14.110:80         TIME_WAIT
udp      0.0.0.0:53                *:*                       -

Total: 5 connections
```

### With Process IDs
```
PROTO    LOCAL                     REMOTE                    STATE           PID
────────────────────────────────────────────────────────────────────────────────
tcp      0.0.0.0:22                *:*                       LISTEN          1234
tcp      0.0.0.0:80                *:*                       LISTEN          5678
tcp      192.168.1.100:52341       93.184.216.34:443         ESTABLISHED     9012

Total: 3 connections
```

### Routing Table
```
DESTINATION        GATEWAY            MASK               INTERFACE    METRIC
────────────────────────────────────────────────────────────────────────────────
0.0.0.0            192.168.1.1        0.0.0.0            eth0         100
192.168.1.0        0.0.0.0            255.255.255.0      eth0         100
127.0.0.0          0.0.0.0            255.0.0.0          lo           1

Total: 3 routes
```

## Connection States

| State | Description |
|-------|-------------|
| `LISTEN` | Waiting for incoming connections |
| `ESTABLISHED` | Active connection |
| `TIME_WAIT` | Waiting for packets to clear |
| `CLOSE_WAIT` | Remote side closed connection |
| `SYN_SENT` | Connection request sent |
| `SYN_RECV` | Connection request received |
| `FIN_WAIT1` | Closing connection (waiting for ACK) |
| `FIN_WAIT2` | Closing connection (ACK received) |
| `CLOSING` | Both sides closing simultaneously |
| `LAST_ACK` | Waiting for final ACK |
| `CLOSED` | Connection closed |

## How It Works

- **Windows**: Parses output from `netstat -ano`
- **Linux**: Uses `ss -tuln` or falls back to `netstat`
- **macOS**: Parses output from `netstat -anv`

Routing table:
- **Windows**: Parses `route print`
- **Linux**: Uses `ip route` or `route -n`
- **macOS**: Parses `netstat -rn`

## Use Cases

1. **Security auditing** - Check for unexpected listening ports
2. **Troubleshooting** - Diagnose connection issues
3. **Monitoring** - View active network connections
4. **Network analysis** - Examine routing configuration

## Notes

- Process information (`--pid`) requires administrator/root privileges
- Connection states only apply to TCP (UDP is stateless)
- Some connections may disappear quickly (e.g., TIME_WAIT)
