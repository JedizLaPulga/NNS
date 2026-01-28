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

	"github.com/jedizlapulga/nns/internal/httpstress"
)

func runHTTPStress(args []string) {
	fs := flag.NewFlagSet("httpstress", flag.ExitOnError)
	method := fs.String("method", "GET", "HTTP method")
	concurrency := fs.Int("concurrency", 10, "Number of concurrent workers")
	requests := fs.Int("requests", 100, "Total number of requests")
	duration := fs.Duration("duration", 0, "Test duration (overrides -requests)")
	timeout := fs.Duration("timeout", 30*time.Second, "Request timeout")
	headers := fs.String("headers", "", "Custom headers (key:value,key2:value2)")
	body := fs.String("body", "", "Request body")
	insecure := fs.Bool("insecure", false, "Skip TLS verification")
	noKeepAlive := fs.Bool("no-keepalive", false, "Disable keep-alive")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns httpstress [OPTIONS] <url>

HTTP load/stress testing with detailed metrics.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
    nns httpstress https://api.example.com
    nns httpstress https://api.example.com -requests 1000 -concurrency 50
    nns httpstress https://api.example.com -duration 30s
    nns httpstress https://api.example.com -method POST -body '{"test":true}'
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	url := fs.Arg(0)

	opts := httpstress.Options{
		URL:           url,
		Method:        *method,
		Concurrency:   *concurrency,
		TotalRequests: *requests,
		Duration:      *duration,
		Timeout:       *timeout,
		Body:          *body,
		InsecureSkip:  *insecure,
		KeepAlive:     !*noKeepAlive,
		Headers:       make(map[string]string),
	}

	// Parse headers
	if *headers != "" {
		pairs := strings.Split(*headers, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				opts.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	tester := httpstress.NewTester(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nStopping test...")
		cancel()
	}()

	fmt.Printf("Starting HTTP stress test\n")
	fmt.Printf("  Target:      %s\n", url)
	fmt.Printf("  Method:      %s\n", opts.Method)
	fmt.Printf("  Concurrency: %d\n", opts.Concurrency)
	if opts.Duration > 0 {
		fmt.Printf("  Duration:    %v\n", opts.Duration)
	} else {
		fmt.Printf("  Requests:    %d\n", opts.TotalRequests)
	}
	fmt.Println()

	progressFn := func(current, total int64, stats httpstress.Stats) {
		if total > 0 {
			pct := float64(current) / float64(total) * 100
			fmt.Printf("\rProgress: %d/%d (%.1f%%) | %.1f req/s | Avg: %v",
				current, total, pct, stats.RequestsPerSec,
				stats.AvgLatency.Round(time.Millisecond))
		} else {
			fmt.Printf("\rRequests: %d | %.1f req/s | Avg: %v",
				current, stats.RequestsPerSec,
				stats.AvgLatency.Round(time.Millisecond))
		}
	}

	stats, err := tester.Run(ctx, progressFn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n")
	fmt.Print(stats.Format())
}
