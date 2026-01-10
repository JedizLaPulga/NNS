# nns ssl

Analyze SSL/TLS certificates with security grading.

## Usage

```bash
nns ssl [HOST[:PORT]] [OPTIONS]
```

## Options

| Option | Description |
|--------|-------------|
| `--chain` | Show full certificate chain |
| `--json` | Output in JSON format (for scripting) |
| `--expiry` | Show only expiry information |
| `--grade` | Show only security grade |
| `--timeout` | Connection timeout (default: 10s) |
| `--help` | Show help message |

## Security Grades

| Grade | Description |
|-------|-------------|
| **A+** | Excellent - No issues, TLS 1.2+, strong cipher |
| **A** | Good - Minor warnings only |
| **B** | Acceptable - Some issues |
| **C** | Weak - Multiple issues |
| **D** | Insecure - Critical issues |
| **F** | Fail - Expired, weak crypto, or self-signed |

## What It Checks

- **Certificate validity** (expired, not yet valid)
- **Self-signed certificates**
- **Weak signature algorithms** (SHA1, MD5)
- **Short key sizes** (<2048 RSA, <256 ECDSA)
- **TLS version** (warns on TLS 1.0/1.1)
- **Weak cipher suites** (RC4, DES, 3DES, NULL, EXPORT)
- **Certificate chain completeness**
- **Trusted root presence**

## Examples

### Basic analysis
```bash
nns ssl google.com
```

### Custom port
```bash
nns ssl example.com:8443
```

### Show certificate chain
```bash
nns ssl github.com --chain
```

### JSON output (for scripting/monitoring)
```bash
nns ssl example.com --json
```

### Quick expiry check
```bash
nns ssl example.com --expiry
# Output: example.com:443 — GOOD: 245 days
```

### Just the grade
```bash
nns ssl example.com --grade
# Output: example.com:443 — Grade: A+ (Score: 100/100)
```

## Output Example

```
SSL/TLS Analysis for google.com:443
═══════════════════════════════════════════════════════════════

  Security Grade: A+ (Score: 100/100)

─── Certificate ────────────────────────────────────────────────
  Subject:      CN=*.google.com
  Issuer:       CN=GTS CA 1C3,O=Google Trust Services LLC,C=US
  Serial:       12345678901234567890
  Valid From:   2024-01-15 00:00:00
  Valid Until:  2024-04-14 23:59:59
  Expiry:       GOOD: 245 days
  SANs:         *.google.com, google.com, *.google.co.uk

─── Cryptography ───────────────────────────────────────────────
  Signature:    SHA256-RSA
  Public Key:   ECDSA (256 bits)
  Fingerprint:  a1b2c3d4e5f6...

─── Connection ─────────────────────────────────────────────────
  TLS Version:  TLS 1.3
  Cipher Suite: TLS_AES_256_GCM_SHA384
  Connect Time: 45ms
```
