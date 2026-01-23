package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/conntest"
)

func runConnTest(args []string) {
	fs := flag.NewFlagSet("conntest", flag.ExitOnError)
	timeout := fs.Duration("t", 5*time.Second, "Connection timeout")
	concurrency := fs.Int("c", 10, "Concurrent connections")
	common := fs.Bool("common", false, "Test common targets (DNS, HTTPS)")
	tls := fs.Bool("tls", false, "Use TLS for all targets")
	sort := fs.Bool("sort", false, "Sort results by latency")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns conntest [options] <host:port> [host:port...]\n\n")
		fmt.Fprintf(os.Stderr, "Test connectivity to multiple hosts in parallel.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns conntest google.com:443 github.com:443\n")
		fmt.Fprintf(os.Stderr, "  nns conntest --common\n")
		fmt.Fprintf(os.Stderr, "  nns conntest --tls example.com:443\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	var targets []conntest.Target

	if *common {
		targets = conntest.CommonTargets()
	}

	for _, arg := range fs.Args() {
		target, err := conntest.ParseTarget(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid target %q: %v\n", arg, err)
			os.Exit(1)
		}
		if *tls {
			target.Protocol = conntest.TLS
		}
		targets = append(targets, target)
	}

	if len(targets) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	fmt.Printf("Testing %d targets (concurrency=%d, timeout=%v)\n\n", len(targets), *concurrency, *timeout)

	cfg := conntest.Config{
		Timeout:     *timeout,
		Concurrency: *concurrency,
	}

	tester := conntest.New(cfg)
	ctx := context.Background()
	results := tester.Test(ctx, targets)

	if *sort {
		conntest.SortByLatency(results)
	}

	for _, r := range results {
		fmt.Println(conntest.FormatResult(r))
	}

	fmt.Println()
	fmt.Println(conntest.FormatSummary(conntest.Summarize(results)))
}
