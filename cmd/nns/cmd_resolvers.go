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

	"github.com/JedizLaPulga/NNS/internal/resolvers"
)

func runResolvers(args []string) {
	fs := flag.NewFlagSet("resolvers", flag.ExitOnError)
	queries := fs.Int("queries", 5, "Number of queries per resolver")
	timeout := fs.Duration("timeout", 5*time.Second, "Query timeout")
	domain := fs.String("domain", "google.com", "Test domain")
	all := fs.Bool("all", false, "Test all known public resolvers")
	noSystem := fs.Bool("no-system", false, "Skip system DNS test")
	category := fs.String("category", "", "Filter by category (speed, privacy, security, family, adblock)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns resolvers [OPTIONS]

Compare DNS resolvers for speed, reliability, and privacy.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
CATEGORIES:
    speed     - Fast resolvers (Google, Cloudflare)
    privacy   - No-logging resolvers (Cloudflare, Quad9)
    security  - Malware blocking (Quad9)
    family    - Adult content filtering
    adblock   - Ad blocking (AdGuard)

EXAMPLES:
    nns resolvers
    nns resolvers --all
    nns resolvers --category privacy
    nns resolvers --domain example.com --queries 10
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	cfg := resolvers.Config{
		QueryCount:    *queries,
		Timeout:       *timeout,
		TestDomain:    *domain,
		IncludeSystem: !*noSystem,
	}

	// Determine which resolvers to test
	if *all {
		cfg.Resolvers = resolvers.PublicResolvers
	} else if *category != "" {
		cfg.Resolvers = resolvers.GetByCategory(*category)
		if len(cfg.Resolvers) == 0 {
			fmt.Fprintf(os.Stderr, "Unknown category: %s\n", *category)
			fmt.Fprintf(os.Stderr, "Valid categories: speed, privacy, security, family, adblock\n")
			os.Exit(1)
		}
	} else {
		cfg.Resolvers = resolvers.PublicResolvers[:4] // Default: Google + Cloudflare
	}

	comparator := resolvers.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nCancelling...")
		cancel()
	}()

	resolverNames := make([]string, len(cfg.Resolvers))
	for i, r := range cfg.Resolvers {
		resolverNames[i] = r.Name
	}

	fmt.Printf("Comparing DNS resolvers: %s\n", strings.Join(resolverNames, ", "))
	fmt.Printf("Test domain: %s, Queries per resolver: %d\n\n", *domain, *queries)

	result, err := comparator.Compare(ctx)
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(result.Format())
}
