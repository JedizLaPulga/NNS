package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/httphealth"
)

func runHTTPHealth(args []string) {
	fs := flag.NewFlagSet("httphealth", flag.ExitOnError)
	interval := fs.Int("interval", 10, "Check interval in seconds")
	timeout := fs.Int("timeout", 5, "Request timeout in seconds")
	method := fs.String("method", "GET", "HTTP method to use")
	expect := fs.Int("expect", 200, "Expected HTTP status code")
	once := fs.Bool("once", false, "Run a single check and exit")
	headerFlag := fs.String("header", "", "Custom header (key:value), comma-separated for multiple")

	// Short flags
	fs.IntVar(interval, "i", 10, "Interval (s)")
	fs.IntVar(timeout, "t", 5, "Timeout (s)")
	fs.StringVar(method, "m", "GET", "HTTP method")
	fs.BoolVar(once, "1", false, "Single check")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns httphealth [options] <url> [url...]

Continuously monitor HTTP endpoint health with status tracking,
uptime calculation, and latency statistics. Press Ctrl+C to stop
and see the summary.

Options:
  --interval, -i   Check interval in seconds (default: 10)
  --timeout, -t    Request timeout in seconds (default: 5)
  --method, -m     HTTP method: GET, HEAD (default: GET)
  --expect         Expected status code (default: 200)
  --once, -1       Run a single check round and exit
  --header         Custom header as key:value (comma-separated)
  --help           Show this help message

Examples:
  nns httphealth https://example.com
  nns httphealth -i 5 https://api.example.com https://www.example.com
  nns httphealth --once https://example.com https://backup.example.com
  nns httphealth --method HEAD --expect 204 https://api.example.com/health
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: at least one URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	urls := fs.Args()
	opts := httphealth.DefaultOptions(urls)
	opts.Interval = time.Duration(*interval) * time.Second
	opts.Timeout = time.Duration(*timeout) * time.Second
	opts.Method = strings.ToUpper(*method)
	opts.ExpectedStatus = *expect

	if *headerFlag != "" {
		opts.Headers = make(map[string]string)
		for _, h := range strings.Split(*headerFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				opts.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	fmt.Printf("HTTP HEALTH MONITOR\n\n")
	fmt.Printf("  Endpoints:  %d\n", len(urls))
	fmt.Printf("  Interval:   %ds\n", *interval)
	fmt.Printf("  Expected:   %d\n", opts.ExpectedStatus)
	fmt.Println()

	if *once {
		results := httphealth.CheckAll(context.Background(), opts)
		fmt.Println(httphealth.FormatRound(results))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	statsMap := make(map[string]*httphealth.EndpointStats)
	round := 0

	go httphealth.Monitor(ctx, opts, func(results []httphealth.Status) {
		round++
		httphealth.AccumulateStats(statsMap, results, opts.MaxHistory)
		fmt.Printf("── Round %d (%s) ──\n", round, time.Now().Format("15:04:05"))
		fmt.Println(httphealth.FormatRound(results))
	})

	<-sigCh
	cancel()
	time.Sleep(100 * time.Millisecond)

	fmt.Printf("\n── Summary ──\n")
	fmt.Println(httphealth.FormatSummary(statsMap))
}
