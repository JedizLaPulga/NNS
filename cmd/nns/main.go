package main

import (
	"fmt"
	"os"
	"runtime"
)

// Build-time variables (injected via -ldflags)
var (
	version = "dev"     // -X main.version=v1.0.0
	commit  = "none"    // -X main.commit=$(git rev-parse --short HEAD)
	date    = "unknown" // -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	command := os.Args[1]

	switch command {
	case "--version", "-v":
		printVersion()

	case "--help", "-h", "help":
		printHelp()
	case "ping":
		runPing(os.Args[2:])
	case "traceroute":
		runTraceroute(os.Args[2:])
	case "portscan":
		runPortScan(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	case "dns":
		runDNS(os.Args[2:])
	case "ssl":
		runSSL(os.Args[2:])
	case "http":
		runHTTP(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	case "sweep":
		runSweep(os.Args[2:])
	case "arp":
		runARP(os.Args[2:])
	case "whois":
		runWhois(os.Args[2:])
	case "netstat":
		runNetstat(os.Args[2:])
	case "wol":
		runWOL(os.Args[2:])
	case "headers":
		runHeaders(os.Args[2:])
	case "ipinfo":
		runIPInfo(os.Args[2:])
	case "cidr":
		runCIDR(os.Args[2:])
	case "mac":
		runMAC(os.Args[2:])
	case "mtr":
		runMTR(os.Args[2:])
	case "interfaces", "ifaces":
		runInterfaces(os.Args[2:])
	case "speedtest":
		runSpeedtest(os.Args[2:])
	case "netwatch":
		runNetwatch(os.Args[2:])
	case "tcptest":
		runTCPTest(os.Args[2:])
	case "bwmon":
		runBWMon(os.Args[2:])
	case "services":
		runServices(os.Args[2:])
	case "latency":
		runLatency(os.Args[2:])
	case "forward":
		runPortForward(os.Args[2:])
	case "conntest":
		runConnTest(os.Args[2:])
	case "dnstrace":
		runDNSTrace(os.Args[2:])
	case "listen":
		runListen(os.Args[2:])
	case "urlcheck":
		runURLCheck(os.Args[2:])
	case "pcap":
		runPcap(os.Args[2:])
	case "netpath":
		runNetpath(os.Args[2:])
	case "httpstress":
		runHTTPStress(os.Args[2:])
	case "sshscan":
		runSSHScan(os.Args[2:])
	case "dnsperf":
		runDNSPerf(os.Args[2:])
	case "websocket", "ws":
		runWebSocket(os.Args[2:])
	case "tlscheck":
		runTLSCheck(os.Args[2:])
	case "routes":
		runRoutes(os.Args[2:])
	case "geoloc", "geo":
		runGeoloc(os.Args[2:])
	case "subnet":
		runSubnet(os.Args[2:])
	case "wakewait", "ww":
		runWakeWait(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	help := `NNS - Network Swiss Army Knife

A powerful networking toolkit for sysadmins and developers.

USAGE:
    nns [COMMAND] [OPTIONS]

COMMANDS:
    ping         Send ICMP echo requests to a host
    traceroute   Trace the network path to a host
    mtr          My TraceRoute - continuous ping + traceroute
    portscan     Scan ports on a target host or network
    bench        Benchmark HTTP endpoints
    dns          Perform DNS lookups (A, MX, TXT, etc.)
    ssl          Analyze SSL/TLS certificates
    http         HTTP client with timing breakdown
    proxy        Start a local debugging proxy server
    sweep        Discover live hosts on a network (CIDR scan)
    arp          View ARP table with MAC vendor lookup
    whois        WHOIS lookup for domains and IPs
    netstat      Show network connections and routing
    wol          Wake-on-LAN - power on remote machines
    headers      Analyze HTTP security headers
    ipinfo       IP geolocation and ASN lookup
    cidr         CIDR/subnet calculator
    mac          MAC address utilities
    interfaces   List network interfaces with details
    speedtest    Bandwidth speed test
    netwatch     Monitor network changes in real-time
    tcptest      TCP connectivity test with timing breakdown
    bwmon        Real-time bandwidth monitor
    services     Service detection via banner grabbing
    latency      Continuous latency monitoring with sparkline
    forward      TCP port forwarding / tunnel
    conntest     Test connectivity to multiple hosts
    dnstrace     Trace DNS resolution chain
    listen       TCP/UDP listener for connectivity testing
    urlcheck     Check health of multiple URLs
    pcap         Packet capture and analysis
    netpath      Network path quality analysis
    httpstress   HTTP load/stress testing
    sshscan      SSH server security audit
    dnsperf      DNS resolver performance benchmark
    websocket    WebSocket connectivity and latency tester
    tlscheck     TLS certificate chain validator
    routes       View and analyze routing table
    geoloc       IP geolocation with city, country, ASN info
    subnet       Subnet calculator (split, merge, contains)
    wakewait     Wake-on-LAN + wait for host to come online

OPTIONS:
    --version, -v    Show version information
    --help, -h       Show this help message

Use "nns [COMMAND] --help" for more information about a command.

EXAMPLES:
    nns ping google.com
    nns portscan 192.168.1.1 --ports 80,443
    nns bench https://api.example.com --requests 1000
    nns dns google.com --type MX
    nns ssl google.com --chain
    nns http https://api.example.com --timing
    nns mtr google.com --count 10
    nns interfaces --active
    nns speedtest
`
	fmt.Print(help)
}

func printVersion() {
	fmt.Printf("nns version %s\n", version)
	if commit != "none" {
		fmt.Printf("  commit:  %s\n", commit)
	}
	if date != "unknown" {
		fmt.Printf("  built:   %s\n", date)
	}
	fmt.Printf("  go:      %s\n", runtime.Version())
	fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
