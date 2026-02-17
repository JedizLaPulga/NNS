package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/dnsenum"
)

func runDNSEnum(args []string) {
	fs := flag.NewFlagSet("dnsenum", flag.ExitOnError)
	concurrency := fs.Int("concurrency", 10, "Number of concurrent lookups")
	timeout := fs.Int("timeout", 3, "DNS query timeout in seconds")
	noZoneXfer := fs.Bool("no-axfr", false, "Skip zone transfer attempts")
	resolver := fs.String("resolver", "", "Custom DNS resolver (e.g., 8.8.8.8)")

	// Short flags
	fs.IntVar(concurrency, "c", 10, "Concurrency")
	fs.IntVar(timeout, "t", 3, "Timeout (s)")
	fs.StringVar(resolver, "r", "", "Resolver")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns dnsenum [options] <domain>

Enumerate subdomains of a domain using a built-in wordlist of common
subdomain names. Optionally attempts zone transfers (AXFR) against
authoritative nameservers.

Options:
  --concurrency, -c   Concurrent DNS lookups (default: 10)
  --timeout, -t       DNS query timeout in seconds (default: 3)
  --no-axfr           Skip zone transfer attempts
  --resolver, -r      Custom DNS resolver (e.g., 8.8.8.8)
  --help              Show this help message

Examples:
  nns dnsenum example.com
  nns dnsenum -c 20 example.com
  nns dnsenum --resolver 8.8.8.8 example.com
  nns dnsenum --no-axfr example.com
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: domain required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	domain := fs.Arg(0)
	opts := dnsenum.DefaultOptions(domain)
	opts.Concurrency = *concurrency
	opts.Timeout = time.Duration(*timeout) * time.Second
	opts.TryZoneXfer = !*noZoneXfer
	opts.Resolver = *resolver

	fmt.Printf("DNS ENUMERATION\n\n")
	fmt.Printf("  Domain:       %s\n", domain)
	fmt.Printf("  Wordlist:     %d entries\n", len(opts.Wordlist))
	fmt.Printf("  Concurrency:  %d\n", opts.Concurrency)
	if opts.Resolver != "" {
		fmt.Printf("  Resolver:     %s\n", opts.Resolver)
	}
	fmt.Printf("  Zone Xfer:    %v\n", opts.TryZoneXfer)
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	summary := dnsenum.Enumerate(ctx, opts)

	fmt.Printf("── Results ──\n")
	fmt.Println(dnsenum.FormatSummary(summary))
}
