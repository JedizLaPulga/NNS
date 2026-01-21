package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/portscan"
	"github.com/JedizLaPulga/NNS/internal/sweep"
)

func runSweep(args []string) {
	fs := flag.NewFlagSet("sweep", flag.ExitOnError)

	timeoutFlag := fs.Duration("timeout", 1*time.Second, "Timeout per host")
	concurrentFlag := fs.Int("concurrent", 256, "Number of concurrent workers")
	portsFlag := fs.String("ports", "80,443,22,445,3389", "Ports to check for TCP method")
	resolveFlag := fs.Bool("resolve", true, "Resolve hostnames")

	// Short flags
	fs.DurationVar(timeoutFlag, "t", 1*time.Second, "Timeout")
	fs.IntVar(concurrentFlag, "c", 256, "Concurrent workers")
	fs.StringVar(portsFlag, "p", "80,443,22,445,3389", "Ports")
	fs.BoolVar(resolveFlag, "r", true, "Resolve hostnames")

	fs.Usage = func() {
		fmt.Println(`Usage: nns sweep [CIDR] [OPTIONS]

Discover live hosts on a network using TCP probes.

OPTIONS:
  -t, --timeout      Timeout per host (default: 1s)
  -c, --concurrent   Number of concurrent workers (default: 256)
  -p, --ports        Ports to check (default: 80,443,22,445,3389)
  -r, --resolve      Resolve hostnames (default: true)
      --help         Show this help message

EXAMPLES:
  nns sweep 192.168.1.0/24
  nns sweep 10.0.0.0/16 --timeout 2s
  nns sweep 172.16.0.0/24 --ports 22,80,443,8080`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: CIDR range required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	cidr := fs.Arg(0)

	// Parse ports
	ports, err := portscan.ParsePortRange(*portsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing ports: %v\n", err)
		os.Exit(1)
	}

	cfg := sweep.Config{
		CIDR:        cidr,
		Timeout:     *timeoutFlag,
		Concurrency: *concurrentFlag,
		Method:      "tcp",
		Ports:       ports,
		Resolve:     *resolveFlag,
	}

	sweeper := sweep.NewSweeper(cfg)

	// Count hosts
	hostCount, _ := sweep.CountHosts(cidr)
	fmt.Printf("Sweeping %s (%d hosts)...\n\n", cidr, hostCount)

	fmt.Printf("%-16s %-8s %-30s %s\n", "IP", "PORT", "HOSTNAME", "LATENCY")
	fmt.Println("────────────────────────────────────────────────────────────────")

	ctx := context.Background()
	aliveCount := 0

	results, err := sweeper.Sweep(ctx, func(r sweep.HostResult) {
		aliveCount++
		hostname := r.Hostname
		if hostname == "" {
			hostname = "-"
		}
		if len(hostname) > 28 {
			hostname = hostname[:25] + "..."
		}
		fmt.Printf("%-16s %-8d %-30s %v\n", r.IP, r.Port, hostname, r.Latency.Round(time.Millisecond))
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n────────────────────────────────────────────────────────────────\n")
	fmt.Printf("Scan complete: %d/%d hosts alive\n", aliveCount, len(results))
}
