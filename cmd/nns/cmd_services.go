package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/services"
)

func runServices(args []string) {
	fs := flag.NewFlagSet("services", flag.ExitOnError)
	portsFlag := fs.String("ports", "", "Ports to scan (e.g., '22,80,443' or '1-1000')")
	topFlag := fs.Int("top", 0, "Scan top N common ports")
	timeoutFlag := fs.Duration("timeout", 5*time.Second, "Connection timeout")
	concurrencyFlag := fs.Int("concurrency", 10, "Number of parallel scans")
	noTLSFlag := fs.Bool("no-tls", false, "Don't try TLS connections")
	noProbesFlag := fs.Bool("no-probes", false, "Don't send protocol probes")
	jsonFlag := fs.Bool("json", false, "Output JSON format")
	openOnlyFlag := fs.Bool("open", false, "Show only open ports")

	// Short flags
	fs.StringVar(portsFlag, "p", "", "Ports to scan")
	fs.IntVar(topFlag, "n", 0, "Scan top N common ports")
	fs.DurationVar(timeoutFlag, "t", 5*time.Second, "Timeout")
	fs.IntVar(concurrencyFlag, "c", 10, "Concurrency")
	fs.BoolVar(openOnlyFlag, "o", false, "Show only open ports")

	fs.Usage = func() {
		fmt.Println(`Usage: nns services [HOST] [OPTIONS]

Detect services running on open ports via banner grabbing.

OPTIONS:
  --ports, -p      Ports to scan (e.g., '22,80,443' or '20-25')
  --top, -n        Scan top N common ports (default: all common ports)
  --timeout, -t    Connection timeout (default: 5s)
  --concurrency,-c Number of parallel scans (default: 10)
  --no-tls         Don't attempt TLS connections
  --no-probes      Don't send protocol probes
  --open, -o       Show only open ports
  --json           Output in JSON format
  --help           Show this help message

EXAMPLES:
  nns services scanme.nmap.org
  nns services 192.168.1.1 -p 22,80,443,8080
  nns services example.com --top 20
  nns services example.com -p 1-100 --open`)
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

	// Determine ports to scan
	var ports []int
	if *portsFlag != "" {
		var err error
		ports, err = parsePorts(*portsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing ports: %v\n", err)
			os.Exit(1)
		}
	} else if *topFlag > 0 {
		ports = services.TopPorts(*topFlag)
	} else {
		ports = services.CommonPorts()
	}

	scanner := services.NewScanner(host, ports)
	scanner.Timeout = *timeoutFlag
	scanner.Concurrency = *concurrencyFlag
	scanner.TryTLS = !*noTLSFlag
	scanner.SendProbes = !*noProbesFlag

	// Handle Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nScan interrupted...")
		cancel()
	}()

	fmt.Printf("Service Detection on %s\n", host)
	fmt.Printf("Scanning %d ports...\n\n", len(ports))

	startTime := time.Now()
	results := scanner.ScanAll(ctx)
	elapsed := time.Since(startTime)

	// Sort by port number
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Filter if needed
	if *openOnlyFlag {
		filtered := make([]services.ServiceInfo, 0)
		for _, r := range results {
			if r.State == "open" {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	if *jsonFlag {
		printServicesJSON(results)
	} else {
		printServicesTable(results)
	}

	// Summary
	openCount := 0
	for _, r := range results {
		if r.State == "open" {
			openCount++
		}
	}
	fmt.Printf("\nScanned %d ports in %v. %d open.\n", len(ports), elapsed.Round(time.Millisecond), openCount)
}

func printServicesTable(results []services.ServiceInfo) {
	fmt.Printf("%-6s %-8s %-15s %-10s %s\n", "PORT", "STATE", "SERVICE", "VERSION", "BANNER")
	fmt.Println(strings.Repeat("─", 80))

	for _, r := range results {
		stateIcon := getStateIcon(r.State)
		tlsIndicator := ""
		if r.TLS {
			tlsIndicator = " 🔒"
		}

		banner := r.Banner
		if len(banner) > 40 {
			banner = banner[:37] + "..."
		}
		banner = strings.ReplaceAll(banner, "\n", " ")
		banner = strings.ReplaceAll(banner, "\r", "")

		fmt.Printf("%-6d %s %-6s %-15s %-10s %s%s\n",
			r.Port,
			stateIcon,
			r.State,
			truncateService(r.Service, 15),
			truncateService(r.Version, 10),
			banner,
			tlsIndicator,
		)
	}
}

func printServicesJSON(results []services.ServiceInfo) {
	fmt.Println("[")
	for i, r := range results {
		comma := ","
		if i == len(results)-1 {
			comma = ""
		}
		fmt.Printf(`  {"port":%d,"state":"%s","service":"%s","version":"%s","tls":%t,"banner":"%s"}%s`+"\n",
			r.Port, r.State, r.Service, escapeJSON(r.Version), r.TLS, escapeJSON(r.Banner), comma)
	}
	fmt.Println("]")
}

func getStateIcon(state string) string {
	switch state {
	case "open":
		return "🟢"
	case "closed":
		return "🔴"
	case "filtered":
		return "🟡"
	default:
		return "⚪"
	}
}

func truncateService(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// parsePorts parses a port specification string like "22,80,443" or "1-100" or "22,80,100-200"
func parsePorts(spec string) ([]int, error) {
	var ports []int
	portSet := make(map[int]bool)

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "-") {
			// Range
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[1])
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}

			for p := start; p <= end; p++ {
				if !portSet[p] {
					ports = append(ports, p)
					portSet[p] = true
				}
			}
		} else {
			// Single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			if !portSet[port] {
				ports = append(ports, port)
				portSet[port] = true
			}
		}
	}

	return ports, nil
}
