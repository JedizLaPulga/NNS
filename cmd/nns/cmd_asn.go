package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/JedizLaPulga/NNS/internal/asn"
)

func runASN(args []string) {
	fs := flag.NewFlagSet("asn", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "Lookup timeout")
	noRDAP := fs.Bool("no-rdap", false, "Skip RDAP lookup")

	// Short flags
	fs.DurationVar(timeout, "t", 10*time.Second, "Lookup timeout")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns asn [options] <ip-or-host> [...]

BGP Autonomous System Number lookup via Team Cymru DNS and RDAP.
Shows ASN, organization, prefix, country, and registry for any IP.

Options:
  --timeout, -t    Lookup timeout (default: 10s)
  --no-rdap        Skip RDAP lookup for org details
  --help           Show this help message

Examples:
  nns asn 8.8.8.8                     # Google DNS ASN lookup
  nns asn cloudflare.com              # Resolve hostname first
  nns asn 1.1.1.1 8.8.8.8 9.9.9.9    # Batch lookup
  nns asn 2001:4860:4860::8888        # IPv6 support
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: at least one IP or hostname required\n\n")
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

	opts := asn.LookupOptions{
		Timeout:   *timeout,
		FetchRDAP: !*noRDAP,
	}

	targets := fs.Args()

	if len(targets) == 1 {
		opts.Target = targets[0]
		fmt.Printf("ASN LOOKUP %s\n\n", targets[0])

		info, err := asn.Lookup(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Print(asn.FormatResult(info))
	} else {
		fmt.Printf("ASN BATCH LOOKUP (%d targets)\n\n", len(targets))

		results := asn.LookupBatch(ctx, targets, opts)

		for i, info := range results {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("── %s ──\n", targets[i])
			fmt.Print(asn.FormatResult(info))
		}
	}
}
