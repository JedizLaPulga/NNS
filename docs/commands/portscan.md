# Port Scan Command

Scan ports on target hosts to discover open services.

## Usage

```bash
nns portscan [OPTIONS] <TARGET>
```

## Options

*To be documented when implemented*

## Examples

*To be documented when implemented*

```bash
# Scan common ports on a single host
nns portscan 192.168.1.1 --ports 80,443,8080

# Scan a range of ports
nns portscan 192.168.1.1 --range 1-1024

# Scan entire subnet
nns portscan 192.168.1.0/24 --ports 80,443
```

## Technical Details

*To be documented when implemented*
