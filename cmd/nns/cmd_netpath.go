package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jedizlapulga/nns/internal/netpath"
)

func runNetpath(args []string) {
	fs := flag.NewFlagSet("netpath", flag.ExitOnError)
	maxHops := fs.Int("max-hops", 30, "Maximum number of hops")
	probes := fs.Int("probes", 5, "Number of probes per hop")
	timeout := fs.Duration("timeout", 2*time.Second, "Timeout per probe")
	resolve := fs.Bool("resolve", true, "Resolve hostnames")
	worst := fs.Int("worst", 0, "Show N worst quality hops")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns netpath [OPTIONS] <target>

Analyze network path quality with hop-by-hop scoring.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
    nns netpath google.com
    nns netpath 8.8.8.8 --probes 10
    nns netpath example.com --worst 3
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	opts := netpath.Options{
		MaxHops:      *maxHops,
		ProbesPerHop: *probes,
		Timeout:      *timeout,
		ResolveHosts: *resolve,
	}

	analyzer := netpath.NewAnalyzer(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nCancelling...")
		cancel()
	}()

	fmt.Printf("Analyzing path to %s...\n\n", target)

	result, err := analyzer.Analyze(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(result.Format())

	if *worst > 0 {
		fmt.Printf("\nWorst %d hops:\n", *worst)
		worstHops := result.GetWorstHops(*worst)
		for _, hop := range worstHops {
			host := "*"
			if hop.IP != nil {
				host = hop.IP.String()
				if hop.Hostname != "" {
					host = hop.Hostname
				}
			}
			fmt.Printf("  Hop %d: %s (quality: %.0f%%, loss: %.1f%%)\n",
				hop.Number, host, hop.QualityScore, hop.PacketLoss)
		}
	}
}
