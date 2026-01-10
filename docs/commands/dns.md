# nns dns

Perform DNS lookups for various record types.

## Usage

```bash
nns dns [HOST] [OPTIONS]
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--type` | `-t` | Record type: A, AAAA, MX, TXT, NS, CNAME, PTR (default: A) |
| `--resolver` | `-r` | Custom DNS server (e.g., 8.8.8.8, 1.1.1.1) |
| `--all` | | Query all common record types |
| `--short` | | Show only record values (for scripting) |
| `--help` | | Show help message |

## Supported Record Types

| Type | Description |
|------|-------------|
| `A` | IPv4 addresses |
| `AAAA` | IPv6 addresses |
| `MX` | Mail exchange servers |
| `TXT` | Text records (SPF, DKIM, etc.) |
| `NS` | Name servers |
| `CNAME` | Canonical name (alias) |
| `PTR` | Reverse DNS lookup |

## Examples

### Basic A record lookup
```bash
nns dns google.com
```

### MX records (mail servers)
```bash
nns dns google.com --type MX
```

### TXT records (SPF, DKIM)
```bash
nns dns google.com --type TXT
```

### Reverse DNS (PTR)
```bash
nns dns 8.8.8.8 --type PTR
# or just (auto-detects IP addresses)
nns dns 8.8.8.8
```

### Query all record types
```bash
nns dns google.com --all
```

### Use custom DNS resolver
```bash
nns dns google.com --resolver 1.1.1.1
nns dns google.com --resolver 8.8.8.8
```

### Scripting mode (short output)
```bash
nns dns google.com --short
# Output: 142.250.190.14

# Use in scripts
IP=$(nns dns example.com --short)
```

## Output Format

### Standard output
```
DNS lookup for google.com (type: A)

A       142.250.190.14
        Query time: 12.3ms
```

### MX records with priority
```
DNS lookup for google.com (type: MX)

MX      10 smtp.google.com.
MX      20 smtp2.google.com.
        Query time: 15.7ms
```

### All records
```
DNS lookup for google.com (all types)

A       142.250.190.14
        Query time: 12.3ms

AAAA    2607:f8b0:4004:800::200e
        Query time: 11.1ms

MX      10 smtp.google.com.
        Query time: 15.7ms

TXT     "v=spf1 include:_spf.google.com ~all"
        Query time: 14.2ms
...
```
