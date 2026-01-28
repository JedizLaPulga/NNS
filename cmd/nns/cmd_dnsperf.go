package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jedizlapulga/nns/internal/dnsperf"
)

func runDNSPerf(args []string) {
	fs := flag.NewFlagSet("dnsperf", flag.ExitOnError)
	queries := fs.Int("queries", 10, "Number of queries per resolver")
	concurrency := fs.Int("concurrency", 5, "Concurrent queries")
	timeout := fs.Duration("timeout", 5*time.Second, "Query timeout")
	queryType := fs.String("type", "A", "Query type (A, AAAA, MX, TXT, NS)")
	resolvers := fs.String("resolvers", "", "Custom resolvers (comma-separated, e.g., 8.8.8.8:53,1.1.1.1:53)")
	all := fs.Bool("all", false, "Test all common resolvers")
	compact := fs.Bool("compact", false, "Compact output format")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns dnsperf [OPTIONS] <domain>

Benchmark DNS resolver performance.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
    nns dnsperf google.com
    nns dnsperf google.com --all
    nns dnsperf google.com --queries 50
    nns dnsperf example.com --type MX
    nns dnsperf example.com --resolvers 8.8.8.8:53,9.9.9.9:53
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	domain := fs.Arg(0)

	opts := dnsperf.Options{
		QueryCount:  *queries,
		Concurrency: *concurrency,
		Timeout:     *timeout,
		QueryType:   *queryType,
	}

	// Determine resolvers
	if *resolvers != "" {
		parts := strings.Split(*resolvers, ",")
		for i, addr := range parts {
			addr = strings.TrimSpace(addr)
			if !strings.Contains(addr, ":") {
				addr += ":53"
			}
			opts.Resolvers = append(opts.Resolvers, dnsperf.Resolver{
				Name:    fmt.Sprintf("Custom%d", i+1),
				Address: addr,
			})
		}
	} else if *all {
		opts.Resolvers = dnsperf.CommonResolvers
	} else {
		opts.Resolvers = dnsperf.CommonResolvers[:4] // Google + Cloudflare
	}

	benchmark := dnsperf.NewBenchmark(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nCancelling...")
		cancel()
	}()

	fmt.Printf("Benchmarking DNS resolvers for %s (%s)...\n", domain, *queryType)
	fmt.Printf("Testing %d resolvers with %d queries each\n\n", len(opts.Resolvers), *queries)

	result, err := benchmark.Run(ctx, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *compact {
		fmt.Print(result.FormatCompact())
	} else {
		fmt.Print(result.Format())
	}

	// Show recommendation
	if result.Best != nil {
		fmt.Printf("\n💡 Recommendation: Use %s for best performance\n", result.Best.Resolver.Name)
	}
}
