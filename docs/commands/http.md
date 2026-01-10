# nns http

HTTP client with detailed timing breakdown for debugging and performance analysis.

## Usage

```bash
nns http [URL] [OPTIONS]
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--method` | `-X` | HTTP method (GET, POST, PUT, DELETE, etc.) |
| `--data` | `-d` | Request body data |
| `--header` | `-H` | Add header (format: "Name: Value") |
| `--timing` | | Show detailed timing breakdown |
| `--headers` | | Show response headers |
| `--output` | `-o` | Save response body to file |
| `--json` | | Output in JSON format |
| `--follow` | | Follow redirects (default: true) |
| `--silent` | | Don't print response body |
| `--timeout` | | Request timeout (default: 30s) |

## Timing Breakdown

When using `--timing`, you get:
- **DNS Lookup**: Time to resolve hostname
- **TCP Connect**: Time to establish TCP connection
- **TLS Handshake**: Time for TLS negotiation (HTTPS only)
- **TTFB**: Time to first byte
- **Download**: Time to download response body
- **Total**: Total request time

## Examples

### Basic GET request
```bash
nns http https://api.example.com
```

### With timing breakdown
```bash
nns http https://api.example.com --timing
```

### POST with JSON body
```bash
nns http https://api.example.com -X POST -d '{"key":"value"}'
```

### Custom headers
```bash
nns http https://api.example.com -H "Authorization: Bearer token"
```

### Show response headers
```bash
nns http https://httpbin.org/get --headers
```

### Save to file
```bash
nns http https://example.com -o page.html
```

### JSON output (for scripting)
```bash
nns http https://api.example.com --json
```

## Output Example

```
HTTP/2.0 200 OK
Content-Type: application/json
Content-Length: 1.2 KB

─── Timing ─────────────────────────────────────────────────────
  DNS Lookup:    12ms
  TCP Connect:   45ms
  TLS Handshake: 89ms
  TTFB:          156ms
  Download:      23ms
  ────────────────────
  Total:         179ms

─── Body ───────────────────────────────────────────────────────
{
  "message": "Hello, World!"
}
```
