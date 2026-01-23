package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/JedizLaPulga/NNS/internal/latency"
)

func runLatency(args []string) {
	fs := flag.NewFlagSet("latency", flag.ExitOnError)
	port := fs.Int("p", 443, "Target port")
	count := fs.Int("c", 0, "Number of probes (0 = infinite)")
	interval := fs.Duration("i", time.Second, "Interval between probes")
	timeout := fs.Duration("t", 5*time.Second, "Connection timeout")
	threshold := fs.Duration("threshold", 0, "Alert threshold (e.g., 100ms)")
	sparkWidth := fs.Int("spark", 40, "Sparkline width")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns latency [options] <host>\n\n")
		fmt.Fprintf(os.Stderr, "Continuous latency monitoring with sparkline visualization.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns latency google.com\n")
		fmt.Fprintf(os.Stderr, "  nns latency -c 20 -p 80 example.com\n")
		fmt.Fprintf(os.Stderr, "  nns latency --threshold 50ms google.com\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	cfg := latency.Config{
		Target:    target,
		Port:      *port,
		Interval:  *interval,
		Timeout:   *timeout,
		Threshold: *threshold,
		Count:     *count,
	}

	mon, err := latency.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("LATENCY %s:%d\n", target, *port)
	if *threshold > 0 {
		fmt.Printf("Alert threshold: %v\n", *threshold)
	}
	fmt.Println()

	mon.OnResult(func(r latency.Result) {
		spark := mon.Sparkline(*sparkWidth)
		fmt.Printf("\r%s %s", latency.FormatResult(r, target), spark)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println()
		cancel()
	}()

	err = mon.Run(ctx)
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
	}

	fmt.Println()
	fmt.Println()
	fmt.Print(latency.FormatStats(mon.Stats()))
}
