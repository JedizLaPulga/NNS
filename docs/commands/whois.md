# nns whois

WHOIS lookup for domains and IP addresses.

## Usage

```bash
nns whois [TARGET] [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--server` | `-s` | | Custom WHOIS server |
| `--timeout` | `-t` | `10s` | Query timeout |
| `--raw` | | `false` | Show raw WHOIS response |
| `--help` | | | Show help message |

## Examples

### Domain WHOIS lookup
```bash
nns whois google.com
nns whois amazon.co.uk
```

### IP address WHOIS lookup
```bash
nns whois 8.8.8.8
nns whois 1.1.1.1
```

### Show raw WHOIS response
```bash
nns whois google.com --raw
```

### Use custom WHOIS server
```bash
nns whois example.com --server whois.verisign-grs.com
```

## Output

### Domain WHOIS
```
WHOIS for google.com (domain)
════════════════════════════════════════════════════════════════
  Registrar:      MarkMonitor Inc.
  Organization:   Google LLC
  Created:        1997-09-15T00:00:00Z
  Updated:        2019-09-09T15:39:04Z
  Expires:        2028-09-14T00:00:00Z
                  (1825 days remaining)
  Country:        US
  Name Servers:
                  ns1.google.com
                  ns2.google.com
                  ns3.google.com
                  ns4.google.com

  Server:         whois.verisign-grs.com
  Query Time:     245ms
```

### IP WHOIS
```
WHOIS for 8.8.8.8 (ip)
════════════════════════════════════════════════════════════════
  Organization:   Google LLC
  Network Name:   GOOGLE
  Net Range:      8.8.8.0 - 8.8.8.255
  CIDR:           8.8.8.0/24
  Country:        US

  Server:         whois.arin.net
  Query Time:     312ms
```

## Supported TLDs

The WHOIS client automatically selects the correct WHOIS server for:

- Generic TLDs: `.com`, `.net`, `.org`, `.info`, `.io`, `.co`, `.biz`
- Country TLDs: `.uk`, `.de`, `.fr`, `.nl`, `.eu`, `.ru`, `.cn`, `.au`, `.ca`, `.jp`, etc.
- New TLDs: `.xyz`, `.app`, `.dev`, `.tv`, `.cc`

## IP WHOIS Registries

For IP addresses, the client queries:

- **ARIN** - American Registry (North America)
- **RIPE** - European Registry (Europe, Middle East)
- **APNIC** - Asia Pacific Registry
- **LACNIC** - Latin America Registry
- **AFRINIC** - African Registry

Referrals are automatically followed to get the most accurate information.

## Use Cases

1. **Domain research** - Check registration details and expiry
2. **Security investigation** - Identify IP address ownership
3. **Compliance** - Verify domain registrar information
4. **Monitoring** - Track domain expiration dates

## Notes

- Some registries provide limited information due to GDPR
- Rate limiting may apply for frequent queries
- Use `--raw` to see complete unprocessed response
