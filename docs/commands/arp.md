# nns arp

View the system ARP table with MAC vendor lookup.

## Usage

```bash
nns arp [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface` | `-i` | | Filter by network interface |
| `--vendor` | `-v` | `true` | Show MAC vendor information |
| `--help` | | | Show help message |

## Examples

### View full ARP table
```bash
nns arp
```

### Filter by interface
```bash
nns arp --interface eth0
nns arp -i "Ethernet"
```

### Hide vendor information
```bash
nns arp --vendor=false
```

## Output

```
IP               MAC                  INTERFACE    TYPE            VENDOR
────────────────────────────────────────────────────────────────────────────
192.168.1.1      aa:bb:cc:dd:ee:ff    eth0         dynamic         TP-Link
192.168.1.50     00:0c:29:12:34:56    eth0         dynamic         VMware
192.168.1.100    b8:27:eb:aa:bb:cc    eth0         dynamic         Raspberry Pi

Total: 3 entries
```

## How It Works

The ARP command reads the system's ARP cache:

- **Windows**: Executes `arp -a` and parses output
- **Linux**: Reads from `/proc/net/arp` or uses `arp -n`
- **macOS**: Executes `arp -an` and parses output

MAC vendor lookup uses a built-in OUI database containing common manufacturers.

## Supported Vendors

The built-in OUI database includes:

- Apple, Microsoft, Intel, Samsung
- Cisco, Dell, HP, Lenovo
- TP-Link, Netgear, D-Link, Linksys
- Amazon, Google, Huawei
- Raspberry Pi, Ubiquiti
- VMware, VirtualBox
- And many more...

## Use Cases

1. **Network inventory** - See what devices are on your network
2. **Security auditing** - Detect unknown or rogue devices
3. **Troubleshooting** - Verify device connectivity
4. **MAC identification** - Quickly identify device manufacturers

## Notes

- ARP entries are cached by the OS and may not reflect real-time state
- Entries expire after a period of inactivity
- Only shows devices on the local network segment
