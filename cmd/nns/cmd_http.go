package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/httpclient"
)

func runHTTP(args []string) {
	fs := flag.NewFlagSet("http", flag.ExitOnError)

	methodFlag := fs.String("method", "GET", "HTTP method")
	dataFlag := fs.String("data", "", "Request body data")
	timingFlag := fs.Bool("timing", false, "Show detailed timing breakdown")
	headersFlag := fs.Bool("headers", false, "Show response headers")
	outputFlag := fs.String("output", "", "Save response body to file")
	timeoutFlag := fs.Duration("timeout", 30*time.Second, "Request timeout")
	jsonFlag := fs.Bool("json", false, "Output in JSON format")
	followFlag := fs.Bool("follow", true, "Follow redirects")
	silentFlag := fs.Bool("silent", false, "Don't print response body")

	// Short flags
	fs.StringVar(methodFlag, "X", "GET", "HTTP method")
	fs.StringVar(dataFlag, "d", "", "Request body")
	fs.StringVar(outputFlag, "o", "", "Output file")

	// Headers (simple implementation - one header)
	headerFlag := fs.String("H", "", "Header in 'Name: Value' format")
	fs.StringVar(headerFlag, "header", "", "Header")

	fs.Usage = func() {
		fmt.Println(`Usage: nns http [URL] [OPTIONS]

HTTP client with detailed timing breakdown.

OPTIONS:
  -X, --method    HTTP method (GET, POST, PUT, DELETE, etc.)
  -d, --data      Request body data
  -H, --header    Add header (format: "Name: Value")
      --timing    Show detailed timing breakdown
      --headers   Show response headers
  -o, --output    Save response body to file
      --json      Output in JSON format
      --follow    Follow redirects (default: true)
      --silent    Don't print response body
      --timeout   Request timeout (default: 30s)
      --help      Show this help message

EXAMPLES:
  nns http https://api.example.com
  nns http https://api.example.com --timing
  nns http https://api.example.com -X POST -d '{"key":"value"}'
  nns http https://api.example.com -H "Authorization: Bearer token"
  nns http https://httpbin.org/get --headers
  nns http https://example.com -o page.html`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	url := httpclient.ParseURL(fs.Arg(0))

	// Build request
	req := &httpclient.Request{
		Method:       *methodFlag,
		URL:          url,
		Body:         *dataFlag,
		Timeout:      *timeoutFlag,
		FollowRedirs: *followFlag,
		Headers:      make(map[string]string),
	}

	// Parse header
	if *headerFlag != "" {
		parts := strings.SplitN(*headerFlag, ":", 2)
		if len(parts) == 2 {
			req.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Auto-detect JSON body
	if *dataFlag != "" && strings.HasPrefix(strings.TrimSpace(*dataFlag), "{") {
		req.Headers["Content-Type"] = "application/json"
	}

	// Create client
	client := httpclient.NewClient()
	client.Timeout = *timeoutFlag
	client.FollowRedirects = *followFlag

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// JSON output
	if *jsonFlag {
		jsonOutput, err := resp.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonOutput)
		return
	}

	// Print results
	printHTTPResult(resp, *timingFlag, *headersFlag, *silentFlag)

	// Save to file
	if *outputFlag != "" {
		if err := os.WriteFile(*outputFlag, resp.Body, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Response saved to %s\n", *outputFlag)
	}
}

func printHTTPResult(r *httpclient.Response, showTiming, showHeaders, silent bool) {
	// Status line
	statusColor := ""
	statusReset := ""
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		statusColor = "\033[32m" // Green
		statusReset = "\033[0m"
	} else if r.StatusCode >= 300 && r.StatusCode < 400 {
		statusColor = "\033[33m" // Yellow
		statusReset = "\033[0m"
	} else {
		statusColor = "\033[31m" // Red
		statusReset = "\033[0m"
	}

	fmt.Printf("%s%s%s %s\n", statusColor, r.Proto, statusReset, r.Status)

	// Quick info
	fmt.Printf("Content-Type: %s\n", r.ContentType)
	if r.ContentLength > 0 {
		fmt.Printf("Content-Length: %s\n", httpclient.FormatSize(r.ContentLength))
	} else {
		fmt.Printf("Content-Length: %s\n", httpclient.FormatSize(int64(len(r.Body))))
	}

	// Timing breakdown
	if showTiming {
		fmt.Println("\n─── Timing ─────────────────────────────────────────────────────")
		if r.Timing.DNSLookup > 0 {
			fmt.Printf("  DNS Lookup:    %v\n", r.Timing.DNSLookup.Round(time.Millisecond))
		}
		if r.Timing.TCPConnect > 0 {
			fmt.Printf("  TCP Connect:   %v\n", r.Timing.TCPConnect.Round(time.Millisecond))
		}
		if r.Timing.TLSHandshake > 0 {
			fmt.Printf("  TLS Handshake: %v\n", r.Timing.TLSHandshake.Round(time.Millisecond))
		}
		fmt.Printf("  TTFB:          %v\n", r.Timing.TTFB.Round(time.Millisecond))
		fmt.Printf("  Download:      %v\n", r.Timing.Download.Round(time.Millisecond))
		fmt.Printf("  ────────────────────\n")
		fmt.Printf("  Total:         %v\n", r.Timing.Total.Round(time.Millisecond))
	} else {
		fmt.Printf("Time: %v\n", r.Timing.Total.Round(time.Millisecond))
	}

	// Response headers
	if showHeaders {
		fmt.Println("\n─── Response Headers ───────────────────────────────────────────")
		for k, v := range r.Headers {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	// Body
	if !silent && len(r.Body) > 0 {
		fmt.Println("\n─── Body ───────────────────────────────────────────────────────")
		body := string(r.Body)
		if len(body) > 2000 {
			fmt.Printf("%s\n... (truncated, %d bytes total)\n", body[:2000], len(body))
		} else {
			fmt.Println(body)
		}
	}

	fmt.Println()
}
