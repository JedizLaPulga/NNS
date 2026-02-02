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

	"github.com/JedizLaPulga/NNS/internal/blacklist"
)

func runBlacklist(args []string) {
	fs := flag.NewFlagSet("blacklist", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "Lookup timeout")
	concurrency := fs.Int("concurrency", 10, "Parallel lookups")
	brief := fs.Bool("brief", false, "Brief output")
	noTXT := fs.Bool("no-txt", false, "Skip TXT record lookup")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns blacklist [options] <ip|domain>\n\n")
		fmt.Fprintf(os.Stderr, "Check IP or domain against spam/malware blacklists.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns blacklist 8.8.8.8\n")
		fmt.Fprintf(os.Stderr, "  nns blacklist example.com\n")
		fmt.Fprintf(os.Stderr, "  nns blacklist --brief 192.168.1.1\n")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	opts := blacklist.DefaultOptions()
	opts.Timeout = *timeout
	opts.Concurrency = *concurrency
	opts.IncludeTXT = !*noTXT

	checker := blacklist.NewChecker(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Determine if IP or domain
	var result *blacklist.CheckResult
	var err error

	if isIPAddress(target) {
		fmt.Printf("Checking IP %s against %d blacklists...\n", target, len(opts.Blacklists))
		result, err = checker.CheckIP(ctx, target)
	} else {
		fmt.Printf("Checking domain %s against URI blacklists...\n", target)
		result, err = checker.CheckDomain(ctx, target)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *brief {
		fmt.Println(result.FormatCompact())
	} else {
		fmt.Print(result.Format())
	}

	// Exit code based on listings
	if result.IsClean() {
		os.Exit(0)
	} else if result.TotalListed <= 2 {
		os.Exit(1) // Some listings
	} else {
		os.Exit(2) // Many listings
	}
}

func isIPAddress(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
