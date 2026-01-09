# HTTP Benchmark Command

Performance test HTTP endpoints with detailed latency metrics and support for high concurrency.

## Usage

```bash
nns bench [OPTIONS] <URL>
```

## Options

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--requests` | `-n` | int | 1 | Number of requests to run |
| `--concurrency` | `-c` | int | 1 | Number of concurrent workers |
| `--duration` | `-z` | duration | 0 | Duration of test (overrides -n) |
| `--timeout` | `-t` | duration | 10s | Request timeout |
| `--method` | `-m` | string | GET | HTTP method |
| `--keepalive` | - | bool | true | Use HTTP Keep-Alive |

## Examples

```

## Technical Details

*To be documented when implemented*
