package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/httptrace"
)

func runHTTPTrace(args []string) {
	fs := flag.NewFlagSet("httptrace", flag.ExitOnError)
	method := fs.String("method", "GET", "HTTP method")
	timeout := fs.Duration("timeout", 30*time.Second, "Request timeout")
	maxRedirects := fs.Int("max-redirects", 10, "Maximum redirects to follow")
	noFollow := fs.Bool("no-follow", false, "Don't follow redirects")
	insecure := fs.Bool("insecure", false, "Skip TLS verification")
	headers := fs.String("headers", "", "Custom headers (key:value,key:value)")

	// Short flags
	fs.StringVar(method, "X", "GET", "HTTP method")
	fs.DurationVar(timeout, "t", 30*time.Second, "Request timeout")
	fs.BoolVar(insecure, "k", false, "Skip TLS verification")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns httptrace [options] <url>

Trace HTTP requests through redirect chains with detailed timing breakdown.
Shows DNS, connect, TLS, and TTFB timings for each hop. Inspects security headers.

Options:
  --method, -X       HTTP method (default: GET)
  --timeout, -t      Request timeout (default: 30s)
  --max-redirects    Maximum redirects to follow (default: 10)
  --no-follow        Don't follow redirects
  --insecure, -k     Skip TLS certificate verification
  --headers          Custom headers (key:value,key:value)
  --help             Show this help message

Examples:
  nns httptrace http://example.com              # Trace with redirects
  nns httptrace https://api.example.com -X POST # POST method
  nns httptrace http://t.co/xyz --no-follow     # Don't follow redirects
  nns httptrace https://self-signed.local -k    # Skip TLS verify
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	opts := httptrace.TraceOptions{
		URL:            fs.Arg(0),
		Method:         *method,
		Timeout:        *timeout,
		MaxRedirects:   *maxRedirects,
		FollowRedirect: !*noFollow,
		InsecureSkip:   *insecure,
	}

	if *headers != "" {
		opts.Headers = make(map[string]string)
		for _, h := range strings.Split(*headers, ",") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				opts.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	fmt.Printf("HTTP TRACE %s %s\n\n", opts.Method, opts.URL)

	result, err := httptrace.Trace(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(httptrace.FormatResult(result))
}
