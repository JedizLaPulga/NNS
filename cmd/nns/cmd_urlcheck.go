package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/JedizLaPulga/NNS/internal/urlcheck"
)

func runURLCheck(args []string) {
	fs := flag.NewFlagSet("urlcheck", flag.ExitOnError)
	timeout := fs.Duration("t", 10*time.Second, "Request timeout")
	concurrency := fs.Int("c", 10, "Concurrent requests")
	noFollow := fs.Bool("no-follow", false, "Don't follow redirects")
	insecure := fs.Bool("insecure", false, "Skip TLS certificate verification")
	sort := fs.Bool("sort", false, "Sort results by response time")
	common := fs.Bool("common", false, "Test common endpoints")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns urlcheck [options] <url> [url...]\n\n")
		fmt.Fprintf(os.Stderr, "Check health of multiple URLs.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns urlcheck https://google.com https://github.com\n")
		fmt.Fprintf(os.Stderr, "  nns urlcheck --common\n")
		fmt.Fprintf(os.Stderr, "  nns urlcheck --sort api.example.com/health\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	var targets []urlcheck.Target

	if *common {
		targets = urlcheck.CommonEndpoints()
	}

	// Add command-line URLs
	for _, u := range fs.Args() {
		targets = append(targets, urlcheck.Target{URL: u})
	}

	if len(targets) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	cfg := urlcheck.Config{
		Timeout:      *timeout,
		Concurrency:  *concurrency,
		FollowRedir:  !*noFollow,
		SkipTLSCheck: *insecure,
	}

	checker := urlcheck.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	fmt.Printf("Checking %d URLs (concurrency=%d, timeout=%v)...\n\n", len(targets), *concurrency, *timeout)

	results := checker.CheckMultiple(ctx, targets)

	if *sort {
		urlcheck.SortByResponseTime(results)
	}

	for _, r := range results {
		fmt.Println(urlcheck.FormatResult(r))
	}

	fmt.Println()
	fmt.Println(urlcheck.FormatSummary(urlcheck.Summarize(results)))
}
