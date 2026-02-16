package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/ratelimit"
)

func runRatelimit(args []string) {
	fs := flag.NewFlagSet("ratelimit", flag.ExitOnError)
	count := fs.Int("count", 30, "Number of requests to send")
	delay := fs.Int("delay", 100, "Delay between requests in ms")
	method := fs.String("method", "GET", "HTTP method to use")
	timeout := fs.Int("timeout", 10, "Request timeout in seconds")
	concurrent := fs.Int("concurrent", 1, "Number of concurrent requests")
	verbose := fs.Bool("verbose", false, "Show per-request details")
	headerFlag := fs.String("header", "", "Custom header (key:value), repeatable with comma")

	// Short flags
	fs.IntVar(count, "n", 30, "Number of requests")
	fs.IntVar(delay, "d", 100, "Delay (ms)")
	fs.StringVar(method, "m", "GET", "HTTP method")
	fs.BoolVar(verbose, "V", false, "Verbose")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns ratelimit [options] <url>

Probe an HTTP endpoint to discover rate limiting policies.
Sends repeated requests and analyzes responses for rate limit headers
(X-RateLimit-*, Retry-After) and 429 status codes.

Options:
  --count, -n      Number of requests to send (default: 30)
  --delay, -d      Delay between requests in ms (default: 100)
  --method, -m     HTTP method: GET, HEAD, POST (default: GET)
  --timeout        Request timeout in seconds (default: 10)
  --concurrent     Concurrent requests (default: 1)
  --header         Custom header as key:value (comma-separated for multiple)
  --verbose, -V    Show per-request details
  --help           Show this help message

Examples:
  nns ratelimit https://api.example.com/endpoint
  nns ratelimit -n 50 -d 50 https://api.github.com/users
  nns ratelimit --concurrent 5 https://api.example.com/data
  nns ratelimit --header "Authorization:Bearer tok" https://api.example.com
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	url := fs.Arg(0)
	opts := ratelimit.Options{
		URL:        url,
		Method:     strings.ToUpper(*method),
		Count:      *count,
		Delay:      time.Duration(*delay) * time.Millisecond,
		Timeout:    time.Duration(*timeout) * time.Second,
		Concurrent: *concurrent,
	}

	if *headerFlag != "" {
		opts.Headers = make(map[string]string)
		for _, h := range strings.Split(*headerFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				opts.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	fmt.Printf("RATE LIMIT PROBE\n\n")
	fmt.Printf("  Target:     %s\n", url)
	fmt.Printf("  Method:     %s\n", opts.Method)
	fmt.Printf("  Requests:   %d\n", opts.Count)
	fmt.Printf("  Delay:      %dms\n", *delay)
	if *concurrent > 1 {
		fmt.Printf("  Concurrent: %d\n", *concurrent)
	}
	fmt.Println()

	ctx := context.Background()
	summary := ratelimit.Probe(ctx, opts)

	if *verbose {
		fmt.Printf("── Request Details ──\n")
		fmt.Print(ratelimit.FormatResults(summary.Results))
		fmt.Println()
	}

	fmt.Printf("── Summary ──\n")
	fmt.Print(ratelimit.FormatSummary(summary))
}
