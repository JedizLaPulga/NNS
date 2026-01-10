package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/bench"
	"github.com/JedizLaPulga/NNS/internal/dns"
	"github.com/JedizLaPulga/NNS/internal/httpclient"
	"github.com/JedizLaPulga/NNS/internal/ping"
	"github.com/JedizLaPulga/NNS/internal/portscan"
	"github.com/JedizLaPulga/NNS/internal/proxy"
	"github.com/JedizLaPulga/NNS/internal/ssl"
	"github.com/JedizLaPulga/NNS/internal/traceroute"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	command := os.Args[1]

	switch command {
	case "--version", "-v":
		fmt.Printf("nns version %s\n", version)
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
    portscan     Scan ports on a target host or network
    bench        Benchmark HTTP endpoints
    dns          Perform DNS lookups (A, MX, TXT, etc.)
    ssl          Analyze SSL/TLS certificates
    http         HTTP client with timing breakdown
    proxy        Start a local debugging proxy server

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
    nns proxy --port 8080
`
	fmt.Print(help)
}

func runPortScan(args []string) {
	// Create flagset for portscan command
	fs := flag.NewFlagSet("portscan", flag.ExitOnError)
	portsFlag := fs.String("ports", "", "Comma-separated ports or ranges (e.g., 80,443,8000-9000)")
	commonFlag := fs.Bool("common", false, "Scan common ports")
	timeoutFlag := fs.Duration("timeout", 2*time.Second, "Connection timeout per port")
	concurrentFlag := fs.Int("concurrent", 100, "Number of concurrent workers")

	fs.Usage = func() {
		fmt.Println(`Usage: nns portscan [HOST] [OPTIONS]

Scan ports on a target host or network.

OPTIONS:
  --ports, -p       Comma-separated ports or ranges (required unless --common)
  --common          Use common ports preset
  --timeout         Connection timeout per port (default: 2s)
  --concurrent      Number of concurrent workers (default: 100)
  --help            Show this help message

EXAMPLES:
  nns portscan 192.168.1.1 --ports 80,443
  nns portscan example.com --ports 1-1024
  nns portscan 192.168.1.1 --common
  nns portscan 10.0.0.1 --ports 8000-9000 --timeout 5s`)
	}

	// Parse flags
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Get target host
	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: target host required\n\n")
		fs.Usage()
		os.Exit(1)
	}
	target := fs.Arg(0)

	// Determine which ports to scan
	var ports []int
	var err error

	if *commonFlag {
		ports = portscan.CommonPorts()
	} else if *portsFlag != "" {
		ports, err = portscan.ParsePortRange(*portsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing ports: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Error: must specify --ports or --common\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Parse target (handle CIDR if present)
	hosts, err := portscan.ParseCIDR(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing target: %v\n", err)
		os.Exit(1)
	}

	// Create scanner
	scanner := portscan.NewScanner()
	scanner.Timeout = *timeoutFlag
	scanner.Concurrency = *concurrentFlag

	// Scan each host
	for _, host := range hosts {
		fmt.Printf("\nScanning %s...\n", host)

		results := scanner.ScanPorts(context.Background(), host, ports)

		// Display results
		fmt.Printf("\n%-10s %-10s %s\n", "PORT", "STATE", "BANNER")
		fmt.Println("--------------------------------------------")

		openCount := 0
		for _, result := range results {
			if result.Open {
				openCount++
				banner := result.Banner
				if banner == "" {
					banner = "-"
				}
				// Truncate long banners
				if len(banner) > 30 {
					banner = banner[:27] + "..."
				}
				fmt.Printf("%-10d %-10s %s\n", result.Port, "open", banner)
			}
		}

		if openCount == 0 {
			fmt.Println("No open ports found")
		}

	}
}

func runPing(args []string) {
	// Create flagset for ping command
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	countFlag := fs.Int("count", 0, "Number of pings to send (0 = infinite)")
	intervalFlag := fs.Duration("interval", 1*time.Second, "Time between pings")
	timeoutFlag := fs.Duration("timeout", 4*time.Second, "Timeout per ping")
	sizeFlag := fs.Int("size", 64, "Packet size in bytes")

	// Short flags
	fs.IntVar(countFlag, "c", 0, "Number of pings to send")
	fs.DurationVar(intervalFlag, "i", 1*time.Second, "Time between pings")
	fs.DurationVar(timeoutFlag, "t", 4*time.Second, "Timeout per ping")
	fs.IntVar(sizeFlag, "s", 64, "Packet size in bytes")

	fs.Usage = func() {
		fmt.Println(`Usage: nns ping [HOST] [OPTIONS]

Send ICMP Echo Requests to network hosts (requires admin/root privileges).

OPTIONS:
  --count, -c       Number of pings to send (0 = infinite)
  --interval, -i    Time between pings (default: 1s)
  --timeout, -t     Timeout per ping (default: 4s)
  --size, -s        Packet size in bytes (default: 64)
  --help            Show this help message

EXAMPLES:
  nns ping google.com
  nns ping -c 5 example.com
  nns ping -i 500ms 192.168.1.1`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: target host required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)
	pinger := ping.NewPinger(host)
	pinger.Count = *countFlag
	pinger.Interval = *intervalFlag
	pinger.Timeout = *timeoutFlag
	pinger.PacketSize = *sizeFlag

	// Resolve hostname
	fmt.Printf("Resolving %s...\n", host)
	if err := pinger.Resolve(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("PING %s (%s): %d data bytes\n", host, pinger.ResolvedIP, pinger.PacketSize)

	// Handle Ctrl+C gracefully via context (placeholder for full signal handling)
	ctx := context.Background()

	err := pinger.Run(ctx, func(res ping.PingResult) {
		if res.Error != nil {
			fmt.Printf("Request timeout for seq=%d: %v\n", res.Seq, res.Error)
		} else {
			fmt.Printf("Reply from %s: seq=%d time=%v TTL=%d\n",
				pinger.ResolvedIP, res.Seq, res.RTT, res.TTL)
		}
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError running ping: %v\n", err)
		os.Exit(1)
	}

	// Stats are already calculated by pinger.Run()

	fmt.Printf("\n--- %s ping statistics ---\n", host)
	fmt.Printf("%d packets transmitted, %d received, %.2f%% packet loss\n\n",
		pinger.Stats.Sent, pinger.Stats.Received, pinger.Stats.LossRate)

	if pinger.Stats.Received > 0 {
		fmt.Println("Round-trip times:")
		fmt.Printf("  Minimum:    %v\n", pinger.Stats.MinRTT)
		fmt.Printf("  Average:    %v\n", pinger.Stats.AvgRTT)
		fmt.Printf("  Maximum:    %v\n", pinger.Stats.MaxRTT)
		fmt.Printf("  Median:     %v\n", pinger.Stats.MedianRTT)
		fmt.Printf("  Std Dev:    %v\n", pinger.Stats.StdDev)
		fmt.Printf("  Jitter:     %v\n", pinger.Stats.Jitter)
		fmt.Printf("  95th %%ile:  %v\n", pinger.Stats.P95)
		fmt.Printf("  99th %%ile:  %v\n", pinger.Stats.P99)

		fmt.Printf("\nNetwork Quality: %s\n", pinger.Stats.Quality())

		// Try Reverse DNS
		if name, err := pinger.ReverseDNS(); err == nil {
			fmt.Printf("Reverse DNS:     %s\n", name)
		}

		// Histogram
		fmt.Println(ping.GenerateHistogram(pinger.Stats.RTTs, 40))
	}
}

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)

	// Flags
	requestsFlag := fs.Int("requests", 0, "Number of requests to perform")
	concurrencyFlag := fs.Int("concurrent", 1, "Number of concurrent workers")
	durationFlag := fs.Duration("duration", 0, "Duration of test (overrides requests)")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Request timeout")
	methodFlag := fs.String("method", "GET", "HTTP method")
	keepAliveFlag := fs.Bool("keepalive", true, "Use HTTP Keep-Alive")

	// Short flags aliases
	fs.IntVar(requestsFlag, "n", 0, "Number of requests")
	fs.IntVar(concurrencyFlag, "c", 1, "Concurrency")
	fs.DurationVar(durationFlag, "z", 0, "Duration")
	fs.DurationVar(timeoutFlag, "t", 10*time.Second, "Timeout")
	fs.StringVar(methodFlag, "m", "GET", "Method")

	fs.Usage = func() {
		fmt.Println(`Usage: nns bench [OPTIONS] [URL]

Benchmark HTTP endpoints with high performance.

OPTIONS:
  -n, --requests      Number of requests to run
  -c, --concurrent    Number of concurrent workers
  -z, --duration      Duration of test (e.g. 10s, 2m) - overrides --requests
  -m, --method        HTTP method (GET, POST, etc.)
  -t, --timeout       Request timeout on client side (default: 10s)
      --keepalive     Use HTTP Keep-Alive (default: true)
      --help          Show this help message

EXAMPLES:
  nns bench -n 1000 -c 10 https://example.com
  nns bench -z 30s -c 50 http://localhost:8080
  nns bench -m POST -n 100 https://api.site.com`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	url := fs.Arg(0)

	// Default to 1 requests if neither duration nor count specified
	reqCount := *requestsFlag
	if reqCount == 0 && *durationFlag == 0 {
		reqCount = 1
	}

	cfg := bench.Config{
		URL:              url,
		Method:           *methodFlag,
		RequestCount:     reqCount,
		Duration:         *durationFlag,
		Concurrency:      *concurrencyFlag,
		Timeout:          *timeoutFlag,
		DisableKeepAlive: !*keepAliveFlag,
	}

	fmt.Printf("Benchmarking %s...\n", url)
	if cfg.Duration > 0 {
		fmt.Printf("Running %s test @ %d concurrent workers...\n", cfg.Duration, cfg.Concurrency)
	} else {
		fmt.Printf("Running %d requests @ %d concurrent workers...\n", cfg.RequestCount, cfg.Concurrency)
	}

	summary := bench.Run(context.Background(), cfg)

	fmt.Printf("\n--- Results ---\n")
	fmt.Printf("Total Requests:     %d\n", summary.TotalRequests)
	fmt.Printf("Successful:         %d\n", summary.SuccessCount)
	fmt.Printf("Failed:             %d\n", summary.ErrorCount)
	fmt.Printf("Duration:           %v\n", summary.TotalDuration)
	fmt.Printf("Requests/Sec:       %.2f\n", summary.RequestsPerSec)
	fmt.Printf("Transfer Rate:      %.2f MB/s\n", summary.TransferRate)

	if summary.SuccessCount > 0 {
		fmt.Printf("\n--- Latency (Total) ---\n")
		fmt.Printf("Min:    %v\n", summary.MinLat)
		fmt.Printf("Avg:    %v\n", summary.MeanLat)
		fmt.Printf("Max:    %v\n", summary.MaxLat)
		fmt.Printf("P50:    %v\n", summary.P50Lat)
		fmt.Printf("P95:    %v\n", summary.P95Lat)
		fmt.Printf("P99:    %v\n", summary.P99Lat)

		fmt.Printf("\n--- Latency Breakdown (Avg) ---\n")
		fmt.Printf("DNS:        %v\n", summary.MeanDNS)
		fmt.Printf("Connect:    %v\n", summary.MeanConn)
		fmt.Printf("TLS:        %v\n", summary.MeanTLS)
		fmt.Printf("Wait:       %v\n", summary.MeanWait)

		fmt.Printf("\n--- Status Codes ---\n")
		for code, count := range summary.StatusCodes {
			fmt.Printf("%d: %d\n", code, count)
		}
	}

	if summary.ErrorCount > 0 {
		fmt.Printf("\n--- Errors ---\n")
		for errStr, count := range summary.Errors {
			fmt.Printf("%s: %d\n", errStr, count)
		}
	}
}

func runTraceroute(args []string) {
	fs := flag.NewFlagSet("traceroute", flag.ExitOnError)

	maxHopsFlag := fs.Int("max-hops", 30, "Maximum hops")
	queriesFlag := fs.Int("queries", 3, "Probes per hop")
	timeoutFlag := fs.Duration("timeout", 2*time.Second, "Timeout per hop")
	asFlag := fs.Bool("as", true, "Resolve AS number")

	// Short flags
	fs.IntVar(maxHopsFlag, "m", 30, "Maximum hops")
	fs.IntVar(queriesFlag, "q", 3, "Probes per hop")
	fs.BoolVar(asFlag, "a", true, "Resolve AS number")

	fs.Usage = func() {
		fmt.Println(`Usage: nns traceroute [OPTIONS] [HOST]

Trace route to a destination host.

OPTIONS:
  -m, --max-hops    Maximum hops (default: 30)
  -q, --queries     Probes per hop (default: 3)
  --timeout         Timeout per hop (default: 2s)
  -a, --as          Resolve AS numbers (default: true)
  --help            Show this help message

> **Windows Note**: You may need to allow "File and Printer Sharing (Echo Request - ICMPv4-In)" and "ICMPv4 Time Exceeded" in Windows Firewall to receive replies.

EXAMPLES:
  nns traceroute google.com
  nns traceroute -m 64 example.com`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: host required\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)

	cfg := traceroute.Config{
		Target:    host,
		MaxHops:   *maxHopsFlag,
		Queries:   *queriesFlag,
		Timeout:   *timeoutFlag,
		ResolveAS: *asFlag,
	}

	tracer := traceroute.NewTracer(cfg)

	fmt.Printf("Traceroute to %s, %d hops max\n", host, cfg.MaxHops)
	fmt.Printf("%-3s %-16s %-30s %-20s %s\n", "HOP", "IP", "HOST", "AS/ORG", "RTT")
	fmt.Println("------------------------------------------------------------------------------------------")

	err := tracer.Run(context.Background(), func(h *traceroute.Hop) {
		if h.Timeout {
			fmt.Printf("%-3d *                *                              *                    *\n", h.TTL)
			return
		}

		hostStr := ""
		if len(h.Hosts) > 0 {
			hostStr = h.Hosts[0]
			if len(hostStr) > 28 {
				hostStr = hostStr[:25] + "..."
			}
		} else {
			hostStr = "(" + h.IP + ")"
		}

		asStr := ""
		if h.ASN != "" {
			asStr = fmt.Sprintf("[%s] %s", h.ASN, h.Org)
			if len(asStr) > 19 {
				asStr = asStr[:16] + "..."
			}
		}

		// RTTs
		rttStr := ""
		for _, rtt := range h.RTTs {
			rttStr += fmt.Sprintf("%.1fms ", float64(rtt.Microseconds())/1000.0)
		}
		if len(h.RTTs) < cfg.Queries {
			for i := 0; i < cfg.Queries-len(h.RTTs); i++ {
				rttStr += "* "
			}
		}

		fmt.Printf("%-3d %-16s %-30s %-20s %s\n",
			h.TTL, h.IP, hostStr, asStr, rttStr)
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	portFlag := fs.Int("port", 8080, "Port to listen on")
	verboseFlag := fs.Bool("verbose", false, "Log full request/response details")
	filterFlag := fs.String("filter", "", "Filter logs by domain/keyword")

	// Short flags
	fs.IntVar(portFlag, "p", 8080, "Port to listen on")
	fs.BoolVar(verboseFlag, "v", false, "Log full request/response details")

	fs.Usage = func() {
		fmt.Println(`Usage: nns proxy [OPTIONS]

Start a HTTP/HTTPS debug proxy server.

OPTIONS:
  -p, --port        Port to listen on (default: 8080)
  -v, --verbose     Log verbose details
      --filter      Filter logs by domain/keyword
      --help        Show this help message

EXAMPLES:
  nns proxy
  nns proxy -p 9090 -v
  nns proxy --filter google.com`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg := proxy.Config{
		Port:    *portFlag,
		Verbose: *verboseFlag,
		Filter:  *filterFlag,
	}

	p := proxy.NewProxy(cfg)
	if err := p.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Proxy error: %v\n", err)
		os.Exit(1)
	}
}

func runDNS(args []string) {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)

	typeFlag := fs.String("type", "A", "Record type (A, AAAA, MX, TXT, NS, CNAME, PTR, SOA)")
	resolverFlag := fs.String("resolver", "", "Custom DNS server (e.g., 8.8.8.8)")
	allFlag := fs.Bool("all", false, "Query all common record types")
	shortFlag := fs.Bool("short", false, "Show only record values")
	propagationFlag := fs.Bool("propagation", false, "Check DNS propagation across global resolvers")

	// Short flags
	fs.StringVar(typeFlag, "t", "A", "Record type")
	fs.StringVar(resolverFlag, "r", "", "Custom DNS server")
	fs.BoolVar(propagationFlag, "p", false, "Check propagation")

	fs.Usage = func() {
		fmt.Println(`Usage: nns dns [HOST] [OPTIONS]

Perform DNS lookups for various record types.

OPTIONS:
  -t, --type        Record type: A, AAAA, MX, TXT, NS, CNAME, PTR, SOA (default: A)
  -r, --resolver    Custom DNS server (e.g., 8.8.8.8, 1.1.1.1)
      --all         Query all common record types (A, AAAA, MX, TXT, NS, CNAME, SOA)
  -p, --propagation Check DNS propagation across global resolvers
      --short       Show only record values (for scripting)
      --help        Show this help message

EXAMPLES:
  nns dns google.com                  # A record lookup
  nns dns google.com --type MX        # Mail servers
  nns dns google.com --type TXT       # TXT records (SPF, DKIM)
  nns dns google.com --type SOA       # Authoritative server info
  nns dns 8.8.8.8 --type PTR          # Reverse lookup
  nns dns google.com --all            # All record types
  nns dns google.com --propagation    # Check global DNS propagation
  nns dns google.com --resolver 1.1.1.1`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: hostname or IP required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	// Create resolver
	resolver := dns.NewResolver()
	if *resolverFlag != "" {
		resolver.SetServer(*resolverFlag)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Auto-detect PTR for IP addresses
	recordType := *typeFlag
	if dns.IsIPAddress(target) && recordType == "A" {
		recordType = "PTR"
	}

	if *propagationFlag {
		// Propagation check
		rt, err := dns.ParseRecordType(recordType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Checking DNS propagation for %s (%s)...\n\n", target, rt)

		pr := dns.CheckPropagation(ctx, target, rt)

		fmt.Printf("%-12s %-16s %-10s %s\n", "RESOLVER", "IP", "TIME", "RECORDS")
		fmt.Println("----------------------------------------------------------------")

		for _, r := range pr.Results {
			var recordStr string
			if r.Error != nil {
				recordStr = fmt.Sprintf("ERROR: %v", r.Error)
			} else if len(r.Records) == 0 {
				recordStr = "(no records)"
			} else {
				for i, rec := range r.Records {
					if i > 0 {
						recordStr += ", "
					}
					recordStr += rec.Value
				}
				if len(recordStr) > 35 {
					recordStr = recordStr[:32] + "..."
				}
			}
			fmt.Printf("%-12s %-16s %-10s %s\n", r.Name, r.Resolver, r.Duration.Round(time.Millisecond), recordStr)
		}

		fmt.Println()
		if pr.IsPropagated() {
			fmt.Println("✓ DNS is fully propagated across all resolvers")
		} else {
			fmt.Println("✗ DNS is NOT fully propagated (results differ)")
		}
	} else if *allFlag {
		// Query all types
		fmt.Printf("DNS lookup for %s (all types)\n", target)
		if *resolverFlag != "" {
			fmt.Printf("Using resolver: %s\n", *resolverFlag)
		}
		fmt.Println()

		results := resolver.LookupAll(ctx, target)
		for _, result := range results {
			printDNSResult(&result, *shortFlag)
		}
	} else {
		// Single type query
		rt, err := dns.ParseRecordType(recordType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if !*shortFlag {
			fmt.Printf("DNS lookup for %s (type: %s)\n", target, rt)
			if *resolverFlag != "" {
				fmt.Printf("Using resolver: %s\n", *resolverFlag)
			}
			fmt.Println()
		}

		result := resolver.Lookup(ctx, target, rt)
		printDNSResult(result, *shortFlag)
	}
}

func printDNSResult(result *dns.Result, short bool) {
	if result.Error != nil {
		if !short {
			fmt.Printf("%-6s  (no records: %v)\n", result.Type, result.Error)
		}
		return
	}

	// Handle SOA separately
	if result.Type == dns.TypeSOA && result.SOA != nil {
		if short {
			fmt.Println(result.SOA.PrimaryNS)
			return
		}
		fmt.Printf("%-6s  Primary NS: %s\n", result.Type, result.SOA.PrimaryNS)
		fmt.Printf("        Admin: %s\n", result.SOA.AdminEmail)
		fmt.Printf("        Query time: %v\n\n", result.Duration)
		return
	}

	if len(result.Records) == 0 {
		if !short {
			fmt.Printf("%-6s  (no records)\n", result.Type)
		}
		return
	}

	if short {
		for _, rec := range result.Records {
			fmt.Println(rec.Value)
		}
		return
	}

	// Verbose output
	for _, rec := range result.Records {
		if rec.Priority > 0 {
			fmt.Printf("%-6s  %d %s\n", rec.Type, rec.Priority, rec.Value)
		} else {
			fmt.Printf("%-6s  %s\n", rec.Type, rec.Value)
		}
	}

	fmt.Printf("        Query time: %v\n\n", result.Duration)
}

func runSSL(args []string) {
	fs := flag.NewFlagSet("ssl", flag.ExitOnError)

	chainFlag := fs.Bool("chain", false, "Show full certificate chain")
	jsonFlag := fs.Bool("json", false, "Output in JSON format")
	expiryFlag := fs.Bool("expiry", false, "Show only expiry information")
	gradeFlag := fs.Bool("grade", false, "Show only security grade")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Connection timeout")

	fs.Usage = func() {
		fmt.Println(`Usage: nns ssl [HOST[:PORT]] [OPTIONS]

Analyze SSL/TLS certificates with security grading.

OPTIONS:
      --chain       Show full certificate chain
      --json        Output in JSON format (for scripting)
      --expiry      Show only expiry information
      --grade       Show only security grade
      --timeout     Connection timeout (default: 10s)
      --help        Show this help message

EXAMPLES:
  nns ssl google.com                 # Full analysis
  nns ssl example.com:8443           # Custom port
  nns ssl github.com --chain         # Show certificate chain
  nns ssl example.com --json         # JSON output
  nns ssl example.com --expiry       # Just expiry status
  nns ssl example.com --grade        # Just security grade

SECURITY GRADES:
  A+ : Excellent - No issues, TLS 1.2+, strong cipher
  A  : Good - Minor warnings only
  B  : Acceptable - Some issues
  C  : Weak - Multiple issues
  D  : Insecure - Critical issues
  F  : Fail - Expired, weak crypto, or self-signed`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: hostname required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host, port := ssl.ParseHostPort(fs.Arg(0))

	// Create analyzer
	analyzer := ssl.NewAnalyzer()
	analyzer.Timeout = *timeoutFlag

	result := analyzer.Analyze(host, port)

	if result.Error != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", result.Error)
		os.Exit(1)
	}

	// JSON output
	if *jsonFlag {
		jsonOutput, err := result.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonOutput)
		return
	}

	// Expiry only
	if *expiryFlag {
		fmt.Printf("%s:%d — %s\n", host, port, result.ExpiryStatus())
		return
	}

	// Grade only
	if *gradeFlag {
		fmt.Printf("%s:%d — Grade: %s (Score: %d/100)\n",
			host, port, result.Security.Grade, result.Security.Score)
		return
	}

	// Full output
	printSSLResult(result, *chainFlag)
}

func printSSLResult(r *ssl.Result, showChain bool) {
	fmt.Printf("SSL/TLS Analysis for %s:%d\n", r.Host, r.Port)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Security Grade
	gradeColor := ""
	gradeReset := ""
	switch r.Security.Grade[0] {
	case 'A':
		gradeColor = "\033[32m" // Green
		gradeReset = "\033[0m"
	case 'B':
		gradeColor = "\033[33m" // Yellow
		gradeReset = "\033[0m"
	default:
		gradeColor = "\033[31m" // Red
		gradeReset = "\033[0m"
	}
	fmt.Printf("\n  Security Grade: %s%s%s (Score: %d/100)\n",
		gradeColor, r.Security.Grade, gradeReset, r.Security.Score)

	// Certificate info
	fmt.Println("\n─── Certificate ────────────────────────────────────────────────")
	fmt.Printf("  Subject:      %s\n", r.Certificate.Subject)
	fmt.Printf("  Issuer:       %s\n", r.Certificate.Issuer)
	fmt.Printf("  Serial:       %s\n", truncate(r.Certificate.SerialNumber, 40))
	fmt.Printf("  Valid From:   %s\n", r.Certificate.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Valid Until:  %s\n", r.Certificate.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Expiry:       %s\n", r.ExpiryStatus())

	// SANs
	if len(r.Certificate.SANs) > 0 {
		fmt.Printf("  SANs:         ")
		for i, san := range r.Certificate.SANs {
			if i > 0 {
				fmt.Printf(", ")
			}
			if i == 5 && len(r.Certificate.SANs) > 6 {
				fmt.Printf("... +%d more", len(r.Certificate.SANs)-5)
				break
			}
			fmt.Printf("%s", san)
		}
		fmt.Println()
	}

	// Crypto
	fmt.Println("\n─── Cryptography ───────────────────────────────────────────────")
	fmt.Printf("  Signature:    %s\n", r.Certificate.SignatureAlg)
	fmt.Printf("  Public Key:   %s (%d bits)\n", r.Certificate.PublicKeyAlg, r.Certificate.PublicKeySize)
	fmt.Printf("  Fingerprint:  %s\n", truncate(r.Certificate.Fingerprint, 32)+"...")

	// Connection
	fmt.Println("\n─── Connection ─────────────────────────────────────────────────")
	fmt.Printf("  TLS Version:  %s\n", r.Security.TLSVersion)
	fmt.Printf("  Cipher Suite: %s\n", r.Security.CipherSuite)
	fmt.Printf("  Connect Time: %v\n", r.ConnectTime.Round(time.Millisecond))

	// Issues
	if len(r.Security.Issues) > 0 {
		fmt.Println("\n─── Security Issues ────────────────────────────────────────────")
		for _, issue := range r.Security.Issues {
			icon := "ℹ"
			if issue.Severity == "warning" {
				icon = "⚠"
			} else if issue.Severity == "critical" {
				icon = "✗"
			}
			fmt.Printf("  %s %s\n", icon, issue.Message)
		}
	}

	// Chain
	if showChain && len(r.Chain.Certificates) > 1 {
		fmt.Println("\n─── Certificate Chain ──────────────────────────────────────────")
		for i, cert := range r.Chain.Certificates {
			role := "Leaf"
			if i > 0 && cert.IsCA {
				if i == len(r.Chain.Certificates)-1 {
					role = "Root"
				} else {
					role = "Intermediate"
				}
			}
			fmt.Printf("  [%d] %s (%s)\n", i, truncate(cert.Subject, 50), role)
		}
		fmt.Printf("\n  Chain Complete: %v | Trusted Root: %v\n",
			r.Chain.IsComplete, r.Chain.HasTrustedRoot)
	}

	fmt.Println()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func runHTTP(args []string) {
	fs := flag.NewFlagSet("http", flag.ExitOnError)

	methodFlag := fs.String("method", "GET", "HTTP method")
	dataFlag := fs.String("data", "", "Request body data")
	timingFlag := fs.Bool("timing", false, "Show detailed timing breakdown")
	headersFlag := fs.Bool("headers", false, "Show response headers")
	outputFlag := fs.String("output", "", "Save response body to file")
	timeoutFlag := fs.Duration("timeout", 30*time.Second, "Request timeout")
	jsonFlag := fs.Bool("json", false, "Output in JSON format")
	followFlag := fs.Bool("follow", true, "Follow redirects")
	silentFlag := fs.Bool("silent", false, "Don't print response body")

	// Short flags
	fs.StringVar(methodFlag, "X", "GET", "HTTP method")
	fs.StringVar(dataFlag, "d", "", "Request body")
	fs.StringVar(outputFlag, "o", "", "Output file")

	// Headers (simple implementation - one header)
	headerFlag := fs.String("H", "", "Header in 'Name: Value' format")
	fs.StringVar(headerFlag, "header", "", "Header")

	fs.Usage = func() {
		fmt.Println(`Usage: nns http [URL] [OPTIONS]

HTTP client with detailed timing breakdown.

OPTIONS:
  -X, --method    HTTP method (GET, POST, PUT, DELETE, etc.)
  -d, --data      Request body data
  -H, --header    Add header (format: "Name: Value")
      --timing    Show detailed timing breakdown
      --headers   Show response headers
  -o, --output    Save response body to file
      --json      Output in JSON format
      --follow    Follow redirects (default: true)
      --silent    Don't print response body
      --timeout   Request timeout (default: 30s)
      --help      Show this help message

EXAMPLES:
  nns http https://api.example.com
  nns http https://api.example.com --timing
  nns http https://api.example.com -X POST -d '{"key":"value"}'
  nns http https://api.example.com -H "Authorization: Bearer token"
  nns http https://httpbin.org/get --headers
  nns http https://example.com -o page.html`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	url := httpclient.ParseURL(fs.Arg(0))

	// Build request
	req := &httpclient.Request{
		Method:       *methodFlag,
		URL:          url,
		Body:         *dataFlag,
		Timeout:      *timeoutFlag,
		FollowRedirs: *followFlag,
		Headers:      make(map[string]string),
	}

	// Parse header
	if *headerFlag != "" {
		parts := strings.SplitN(*headerFlag, ":", 2)
		if len(parts) == 2 {
			req.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Auto-detect JSON body
	if *dataFlag != "" && strings.HasPrefix(strings.TrimSpace(*dataFlag), "{") {
		req.Headers["Content-Type"] = "application/json"
	}

	// Create client
	client := httpclient.NewClient()
	client.Timeout = *timeoutFlag
	client.FollowRedirects = *followFlag

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// JSON output
	if *jsonFlag {
		jsonOutput, err := resp.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonOutput)
		return
	}

	// Print results
	printHTTPResult(resp, *timingFlag, *headersFlag, *silentFlag)

	// Save to file
	if *outputFlag != "" {
		if err := os.WriteFile(*outputFlag, resp.Body, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Response saved to %s\n", *outputFlag)
	}
}

func printHTTPResult(r *httpclient.Response, showTiming, showHeaders, silent bool) {
	// Status line
	statusColor := ""
	statusReset := ""
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		statusColor = "\033[32m" // Green
		statusReset = "\033[0m"
	} else if r.StatusCode >= 300 && r.StatusCode < 400 {
		statusColor = "\033[33m" // Yellow
		statusReset = "\033[0m"
	} else {
		statusColor = "\033[31m" // Red
		statusReset = "\033[0m"
	}

	fmt.Printf("%s%s%s %s\n", statusColor, r.Proto, statusReset, r.Status)

	// Quick info
	fmt.Printf("Content-Type: %s\n", r.ContentType)
	if r.ContentLength > 0 {
		fmt.Printf("Content-Length: %s\n", httpclient.FormatSize(r.ContentLength))
	} else {
		fmt.Printf("Content-Length: %s\n", httpclient.FormatSize(int64(len(r.Body))))
	}

	// Timing breakdown
	if showTiming {
		fmt.Println("\n─── Timing ─────────────────────────────────────────────────────")
		if r.Timing.DNSLookup > 0 {
			fmt.Printf("  DNS Lookup:    %v\n", r.Timing.DNSLookup.Round(time.Millisecond))
		}
		if r.Timing.TCPConnect > 0 {
			fmt.Printf("  TCP Connect:   %v\n", r.Timing.TCPConnect.Round(time.Millisecond))
		}
		if r.Timing.TLSHandshake > 0 {
			fmt.Printf("  TLS Handshake: %v\n", r.Timing.TLSHandshake.Round(time.Millisecond))
		}
		fmt.Printf("  TTFB:          %v\n", r.Timing.TTFB.Round(time.Millisecond))
		fmt.Printf("  Download:      %v\n", r.Timing.Download.Round(time.Millisecond))
		fmt.Printf("  ────────────────────\n")
		fmt.Printf("  Total:         %v\n", r.Timing.Total.Round(time.Millisecond))
	} else {
		fmt.Printf("Time: %v\n", r.Timing.Total.Round(time.Millisecond))
	}

	// Response headers
	if showHeaders {
		fmt.Println("\n─── Response Headers ───────────────────────────────────────────")
		for k, v := range r.Headers {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	// Body
	if !silent && len(r.Body) > 0 {
		fmt.Println("\n─── Body ───────────────────────────────────────────────────────")
		body := string(r.Body)
		if len(body) > 2000 {
			fmt.Printf("%s\n... (truncated, %d bytes total)\n", body[:2000], len(body))
		} else {
			fmt.Println(body)
		}
	}

	fmt.Println()
}
