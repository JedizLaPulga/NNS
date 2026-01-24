package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/JedizLaPulga/NNS/internal/dnstrace"
)

func runDNSTrace(args []string) {
	fs := flag.NewFlagSet("dnstrace", flag.ExitOnError)
	queryType := fs.String("type", "A", "Query type (A, AAAA, MX, NS, TXT, CNAME)")
	startServer := fs.String("server", "", "Starting DNS server (default: root servers)")
	maxDepth := fs.Int("depth", 10, "Maximum trace depth")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns dnstrace [options] <domain>\n\n")
		fmt.Fprintf(os.Stderr, "Trace DNS resolution chain from root servers.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns dnstrace google.com\n")
		fmt.Fprintf(os.Stderr, "  nns dnstrace --type MX gmail.com\n")
		fmt.Fprintf(os.Stderr, "  nns dnstrace --server 8.8.8.8 example.com\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	domain := fs.Arg(0)

	cfg := dnstrace.Config{
		QueryType:   strings.ToUpper(*queryType),
		StartServer: *startServer,
		MaxDepth:    *maxDepth,
	}

	tracer := dnstrace.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	fmt.Printf("Tracing DNS resolution for %s (%s)...\n\n", domain, cfg.QueryType)

	trace, err := tracer.TraceResolution(ctx, domain, func(step dnstrace.Step) {
		fmt.Println(dnstrace.FormatStep(step))
	})

	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	if trace.Success {
		fmt.Printf("✓ Resolved: %s\n", strings.Join(trace.FinalIPs, ", "))
	} else if trace.Error != nil {
		fmt.Printf("✕ Failed: %v\n", trace.Error)
	} else {
		fmt.Println("✕ Resolution incomplete")
	}
	fmt.Printf("Total time: %.2fms (%d steps)\n",
		float64(trace.TotalTime.Microseconds())/1000.0, len(trace.Steps))
}
