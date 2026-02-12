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

	"github.com/JedizLaPulga/NNS/internal/reverseproxy"
)

func runFwd(args []string) {
	fs := flag.NewFlagSet("fwd", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "Listen address (host:port)")
	timeout := fs.Duration("timeout", 30*time.Second, "Backend request timeout")
	skipVerify := fs.Bool("insecure", false, "Skip TLS verification for backend")
	addHeader := fs.String("header", "", "Header to inject (Name:Value)")
	rmHeader := fs.String("rm-header", "", "Header to strip from requests")
	brief := fs.Bool("brief", false, "Brief statistics on shutdown")

	// Short flags
	fs.StringVar(listen, "l", ":8080", "Listen address")
	fs.DurationVar(timeout, "t", 30*time.Second, "Timeout")
	fs.BoolVar(skipVerify, "k", false, "Skip TLS verification")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns fwd [options] <backend_url>

HTTP/HTTPS reverse proxy with request logging and statistics.

Proxies all requests from the listen address to the backend URL.
Useful for debugging, traffic inspection, and development.

Options:
  --listen, -l     Listen address (default: :8080)
  --timeout, -t    Backend request timeout (default: 30s)
  --insecure, -k   Skip TLS verification for HTTPS backends
  --header         Inject header (format: Name:Value)
  --rm-header      Strip header from outgoing requests
  --brief          Only show stats on shutdown (no per-request logs)
  --help           Show this help message

Examples:
  nns fwd http://localhost:3000
  nns fwd https://api.example.com -l :9090
  nns fwd http://backend:8080 --header "X-Debug:true"
  nns fwd https://api.internal -k --rm-header Authorization
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: backend URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	backendURL := fs.Arg(0)

	var headers []reverseproxy.HeaderRule
	if *addHeader != "" {
		parts := strings.SplitN(*addHeader, ":", 2)
		if len(parts) == 2 {
			headers = append(headers, reverseproxy.HeaderRule{
				Name:  strings.TrimSpace(parts[0]),
				Value: strings.TrimSpace(parts[1]),
			})
		} else {
			fmt.Fprintf(os.Stderr, "Error: --header format must be Name:Value\n")
			os.Exit(1)
		}
	}
	if *rmHeader != "" {
		headers = append(headers, reverseproxy.HeaderRule{
			Name:   *rmHeader,
			Remove: true,
		})
	}

	opts := reverseproxy.Options{
		ListenAddr:  *listen,
		BackendURL:  backendURL,
		Timeout:     *timeout,
		SkipVerify:  *skipVerify,
		Headers:     headers,
		LogRequests: !*brief,
	}

	if !*brief {
		opts.OnRequest = func(log reverseproxy.RequestLog) {
			status := fmt.Sprintf("%d", log.StatusCode)
			if log.Error != nil {
				status = fmt.Sprintf("ERR: %v", log.Error)
			}
			fmt.Printf("%s  %-6s %-40s  %s  %v\n",
				log.Timestamp.Format("15:04:05"),
				log.Method, log.Path, status,
				log.Latency.Round(time.Microsecond))
		}
	}

	proxy, err := reverseproxy.NewProxy(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		cancel()
	}()

	fmt.Printf("Reverse proxy listening on %s → %s\n", *listen, backendURL)
	if !*brief {
		fmt.Printf("%-8s  %-6s %-40s  %-6s  %s\n", "TIME", "METHOD", "PATH", "STATUS", "LATENCY")
		fmt.Println(strings.Repeat("─", 80))
	}

	if err := proxy.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	fmt.Print(proxy.Stats.Format())
}
