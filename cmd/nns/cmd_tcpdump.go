package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/tcpdump"
)

func runTCPDump(args []string) {
	fs := flag.NewFlagSet("tcpdump", flag.ExitOnError)
	ports := fs.String("ports", "80", "Comma-separated list of ports to probe")
	useTLS := fs.Bool("tls", false, "Attempt TLS handshake on each port")
	timeout := fs.Int("timeout", 10, "Connection timeout in seconds")
	verbose := fs.Bool("verbose", false, "Show detailed per-port breakdown")

	// Short flags
	fs.StringVar(ports, "p", "80", "Ports")
	fs.BoolVar(useTLS, "s", false, "TLS")
	fs.BoolVar(verbose, "V", false, "Verbose")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns tcpdump [options] <host>

Analyze TCP connections: handshake timing, TLS negotiation,
connection state, and address information for one or more ports.

Options:
  --ports, -p    Comma-separated ports (default: 80)
  --tls, -s      Attempt TLS handshake on each port
  --timeout      Connection timeout in seconds (default: 10)
  --verbose, -V  Show detailed per-port breakdown
  --help         Show this help message

Examples:
  nns tcpdump example.com                        # TCP probe port 80
  nns tcpdump -p 80,443,22 example.com           # Multi-port probe
  nns tcpdump --tls -p 443 example.com           # With TLS inspection
  nns tcpdump --tls -p 443,8443 -V example.com   # Verbose multi-port
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: host required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)
	portList := strings.Split(*ports, ",")
	for i, p := range portList {
		portList[i] = strings.TrimSpace(p)
	}

	opts := tcpdump.Options{
		Host:    host,
		Ports:   portList,
		TLS:     *useTLS,
		Timeout: time.Duration(*timeout) * time.Second,
	}

	fmt.Printf("TCP CONNECTION ANALYSIS\n\n")

	ctx := context.Background()

	if len(portList) == 1 && !*verbose {
		ci := tcpdump.Analyze(ctx, host, portList[0], *useTLS, opts.Timeout)
		fmt.Print(tcpdump.FormatConnInfo(ci))
		if !ci.Reachable {
			os.Exit(1)
		}
		return
	}

	mr := tcpdump.AnalyzeMulti(ctx, opts)

	if *verbose {
		for i, ci := range mr.Results {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("── Port %s ──\n", ci.Port)
			fmt.Print(tcpdump.FormatConnInfo(ci))
		}
		fmt.Println()
	}

	fmt.Printf("── Summary ──\n")
	fmt.Print(tcpdump.FormatMultiResult(mr))
}
