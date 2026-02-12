package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/certhunt"
)

func runCerthunt(args []string) {
	fs := flag.NewFlagSet("certhunt", flag.ExitOnError)
	timeout := fs.Duration("timeout", 15*time.Second, "Search timeout")
	noLive := fs.Bool("no-live", false, "Skip live certificate check")
	maxResults := fs.Int("max", 100, "Maximum CT log results")
	brief := fs.Bool("brief", false, "Brief output")

	// Short flags
	fs.DurationVar(timeout, "t", 15*time.Second, "Search timeout")
	fs.IntVar(maxResults, "n", 100, "Maximum CT log results")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns certhunt [options] <domain>

Search Certificate Transparency logs for all certificates issued for a domain.
Also checks the live TLS certificate for comparison.

Options:
  --timeout, -t    Search timeout (default: 15s)
  --max, -n        Maximum CT log results (default: 100)
  --no-live        Skip live certificate check
  --brief          Brief output
  --help           Show this help message

Examples:
  nns certhunt example.com
  nns certhunt github.com -n 50
  nns certhunt internal.corp --no-live
  nns certhunt example.com --brief
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: domain required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	domain := fs.Arg(0)

	opts := certhunt.Options{
		Domain:     domain,
		Timeout:    *timeout,
		CheckLive:  !*noLive,
		MaxResults: *maxResults,
	}

	searcher := certhunt.NewSearcher(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	fmt.Printf("Searching CT logs for %s...\n", domain)

	result, err := searcher.Search(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *brief {
		fmt.Println(result.FormatCompact())
	} else {
		fmt.Print(result.Format())
	}
}
