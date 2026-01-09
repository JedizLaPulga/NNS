package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/ping"
	"github.com/JedizLaPulga/NNS/internal/portscan"
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
		fmt.Println("traceroute command - coming soon")
	case "portscan":
		runPortScan(os.Args[2:])
	case "bench":
		fmt.Println("bench command - coming soon")
	case "proxy":
		fmt.Println("proxy command - coming soon")
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
    proxy        Start a local debugging proxy server

OPTIONS:
    --version, -v    Show version information
    --help, -h       Show this help message

Use "nns [COMMAND] --help" for more information about a command.

EXAMPLES:
    nns ping google.com
    nns portscan 192.168.1.1 --ports 80,443
    nns bench https://api.example.com --requests 1000
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

		results := scanner.ScanPorts(host, ports)

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
			pinger.Stats.AddLost()
		} else {
			fmt.Printf("Reply from %s: seq=%d time=%v TTL=%d\n",
				pinger.ResolvedIP, res.Seq, res.RTT, res.TTL)
			pinger.Stats.AddRTT(res.RTT)
		}
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError running ping: %v\n", err)
		os.Exit(1)
	}

	// Calculate and display statistics
	pinger.Stats.Calculate()

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
