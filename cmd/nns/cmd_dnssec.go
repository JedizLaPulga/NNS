package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/dnssec"
)

func runDNSSEC(args []string) {
	fs := flag.NewFlagSet("dnssec", flag.ExitOnError)
	resolver := fs.String("resolver", "8.8.8.8:53", "DNS resolver to use")
	timeout := fs.Duration("timeout", 10*time.Second, "Query timeout")
	brief := fs.Bool("brief", false, "Brief output")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns dnssec [options] <domain>\n\n")
		fmt.Fprintf(os.Stderr, "Validate DNSSEC chain of trust for a domain.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns dnssec example.com\n")
		fmt.Fprintf(os.Stderr, "  nns dnssec --resolver 1.1.1.1:53 cloudflare.com\n")
		fmt.Fprintf(os.Stderr, "  nns dnssec --brief google.com\n")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	domain := fs.Arg(0)

	opts := dnssec.DefaultOptions()
	opts.Resolver = *resolver
	opts.Timeout = *timeout

	validator := dnssec.NewValidator(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	result, err := validator.Validate(ctx, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *brief {
		printDNSSECBrief(result)
	} else {
		fmt.Print(result.Format())
	}

	// Exit code based on status
	switch result.Status {
	case dnssec.StatusSecure:
		os.Exit(0)
	case dnssec.StatusBogus:
		os.Exit(2)
	default:
		os.Exit(1)
	}
}

func printDNSSECBrief(result *dnssec.ValidationResult) {
	icon := "?"
	switch result.Status {
	case dnssec.StatusSecure:
		icon = "✓"
	case dnssec.StatusInsecure:
		icon = "○"
	case dnssec.StatusBogus:
		icon = "✗"
	}

	fmt.Printf("%s %s: %s (Grade: %s, Score: %d/100)\n",
		icon, result.Domain, result.Status, result.Grade, result.Score)

	if len(result.Issues) > 0 {
		fmt.Printf("  Issues: %d\n", len(result.Issues))
		for _, issue := range result.Issues {
			fmt.Printf("    [%s] %s\n", issue.Severity, issue.Title)
		}
	}
}
