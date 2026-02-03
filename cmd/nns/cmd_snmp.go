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

	"github.com/JedizLaPulga/NNS/internal/snmp"
)

func runSNMP(args []string) {
	fs := flag.NewFlagSet("snmp", flag.ExitOnError)
	community := fs.String("community", "public", "SNMP community string")
	communities := fs.String("communities", "", "Test multiple communities (comma-separated)")
	port := fs.Int("port", 161, "SNMP port")
	timeout := fs.Duration("timeout", 3*time.Second, "Query timeout")
	walk := fs.Bool("walk", true, "Walk common OIDs")
	audit := fs.Bool("audit", true, "Security audit (test common community strings)")
	concurrency := fs.Int("concurrency", 10, "Concurrent scans")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns snmp [OPTIONS] <target>

SNMP device discovery and OID walking.
Target can be an IP address or CIDR range.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
    nns snmp 192.168.1.1
    nns snmp 192.168.1.0/24
    nns snmp 192.168.1.1 --community private
    nns snmp 192.168.1.0/24 --audit
    nns snmp router.local --communities public,private,admin
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

	cfg := snmp.Config{
		Port:          *port,
		Timeout:       *timeout,
		Concurrency:   *concurrency,
		WalkOIDs:      *walk,
		SecurityAudit: *audit,
	}

	// Determine communities to test
	if *communities != "" {
		cfg.Communities = strings.Split(*communities, ",")
	} else {
		cfg.Communities = []string{*community}
	}

	scanner := snmp.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nCancelling...")
		cancel()
	}()

	fmt.Printf("Scanning %s for SNMP devices...\n", target)
	if *audit {
		fmt.Println("Security audit enabled (testing common community strings)")
	}
	fmt.Println()

	result, err := scanner.ScanNetwork(ctx, target)
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(result.Format())
}
