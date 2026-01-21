package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/bench"
)

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)

	// Flags
	requestsFlag := fs.Int("requests", 0, "Number of requests to perform")
	concurrencyFlag := fs.Int("concurrent", 1, "Number of concurrent workers")
	durationFlag := fs.Duration("duration", 0, "Duration of test (overrides requests)")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Request timeout")
	methodFlag := fs.String("method", "GET", "HTTP method")
	keepAliveFlag := fs.Bool("keepalive", true, "Use HTTP Keep-Alive")

	// Short flags aliases
	fs.IntVar(requestsFlag, "n", 0, "Number of requests")
	fs.IntVar(concurrencyFlag, "c", 1, "Concurrency")
	fs.DurationVar(durationFlag, "z", 0, "Duration")
	fs.DurationVar(timeoutFlag, "t", 10*time.Second, "Timeout")
	fs.StringVar(methodFlag, "m", "GET", "Method")

	fs.Usage = func() {
		fmt.Println(`Usage: nns bench [OPTIONS] [URL]

Benchmark HTTP endpoints with high performance.

OPTIONS:
  -n, --requests      Number of requests to run
  -c, --concurrent    Number of concurrent workers
  -z, --duration      Duration of test (e.g. 10s, 2m) - overrides --requests
  -m, --method        HTTP method (GET, POST, etc.)
  -t, --timeout       Request timeout on client side (default: 10s)
      --keepalive     Use HTTP Keep-Alive (default: true)
      --help          Show this help message

EXAMPLES:
  nns bench -n 1000 -c 10 https://example.com
  nns bench -z 30s -c 50 http://localhost:8080
  nns bench -m POST -n 100 https://api.site.com`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	url := fs.Arg(0)

	// Default to 1 requests if neither duration nor count specified
	reqCount := *requestsFlag
	if reqCount == 0 && *durationFlag == 0 {
		reqCount = 1
	}

	cfg := bench.Config{
		URL:              url,
		Method:           *methodFlag,
		RequestCount:     reqCount,
		Duration:         *durationFlag,
		Concurrency:      *concurrencyFlag,
		Timeout:          *timeoutFlag,
		DisableKeepAlive: !*keepAliveFlag,
	}

	fmt.Printf("Benchmarking %s...\n", url)
	if cfg.Duration > 0 {
		fmt.Printf("Running %s test @ %d concurrent workers...\n", cfg.Duration, cfg.Concurrency)
	} else {
		fmt.Printf("Running %d requests @ %d concurrent workers...\n", cfg.RequestCount, cfg.Concurrency)
	}

	summary := bench.Run(context.Background(), cfg)

	fmt.Printf("\n--- Results ---\n")
	fmt.Printf("Total Requests:     %d\n", summary.TotalRequests)
	fmt.Printf("Successful:         %d\n", summary.SuccessCount)
	fmt.Printf("Failed:             %d\n", summary.ErrorCount)
	fmt.Printf("Duration:           %v\n", summary.TotalDuration)
	fmt.Printf("Requests/Sec:       %.2f\n", summary.RequestsPerSec)
	fmt.Printf("Transfer Rate:      %.2f MB/s\n", summary.TransferRate)

	if summary.SuccessCount > 0 {
		fmt.Printf("\n--- Latency (Total) ---\n")
		fmt.Printf("Min:    %v\n", summary.MinLat)
		fmt.Printf("Avg:    %v\n", summary.MeanLat)
		fmt.Printf("Max:    %v\n", summary.MaxLat)
		fmt.Printf("P50:    %v\n", summary.P50Lat)
		fmt.Printf("P95:    %v\n", summary.P95Lat)
		fmt.Printf("P99:    %v\n", summary.P99Lat)

		fmt.Printf("\n--- Latency Breakdown (Avg) ---\n")
		fmt.Printf("DNS:        %v\n", summary.MeanDNS)
		fmt.Printf("Connect:    %v\n", summary.MeanConn)
		fmt.Printf("TLS:        %v\n", summary.MeanTLS)
		fmt.Printf("Wait:       %v\n", summary.MeanWait)

		fmt.Printf("\n--- Status Codes ---\n")
		for code, count := range summary.StatusCodes {
			fmt.Printf("%d: %d\n", code, count)
		}
	}

	if summary.ErrorCount > 0 {
		fmt.Printf("\n--- Errors ---\n")
		for errStr, count := range summary.Errors {
			fmt.Printf("%s: %d\n", errStr, count)
		}
	}
}
