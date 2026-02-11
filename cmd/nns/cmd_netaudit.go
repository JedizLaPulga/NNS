package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/netaudit"
)

func runNetaudit(args []string) {
	fs := flag.NewFlagSet("netaudit", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "Check timeout")
	concurrency := fs.Int("concurrency", 10, "Parallel checks")
	brief := fs.Bool("brief", false, "Brief output")
	noDNS := fs.Bool("no-dns", false, "Skip DNS resolver check")
	noSNMP := fs.Bool("no-snmp", false, "Skip SNMP check")
	noSSH := fs.Bool("no-ssh", false, "Skip SSH check")
	noHTTP := fs.Bool("no-http", false, "Skip HTTP check")
	noTLS := fs.Bool("no-tls", false, "Skip TLS check")
	noPorts := fs.Bool("no-ports", false, "Skip port scan")

	// Short flags
	fs.DurationVar(timeout, "t", 5*time.Second, "Check timeout")
	fs.IntVar(concurrency, "c", 10, "Parallel checks")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns netaudit [options] <host>

Perform a network security audit checking for common misconfigurations.

Checks:
  - Open DNS resolver (DDoS amplification risk)
  - SNMP default community strings
  - SSH version and configuration
  - Telnet exposure
  - HTTP security headers
  - TLS configuration and certificate
  - Open/dangerous ports
  - Service banner leakage

Options:
  --timeout, -t      Check timeout (default: 5s)
  --concurrency, -c  Parallel checks (default: 10)
  --brief            Brief output
  --no-dns           Skip DNS resolver check
  --no-snmp          Skip SNMP check
  --no-ssh           Skip SSH check
  --no-http          Skip HTTP check
  --no-tls           Skip TLS check
  --no-ports         Skip port scan
  --help             Show this help message

Examples:
  nns netaudit 192.168.1.1
  nns netaudit example.com
  nns netaudit 10.0.0.1 --no-dns --no-snmp
  nns netaudit router.local --brief
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: target host required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	opts := netaudit.DefaultOptions()
	opts.Target = target
	opts.Timeout = *timeout
	opts.Concurrency = *concurrency
	opts.CheckDNS = !*noDNS
	opts.CheckSNMP = !*noSNMP
	opts.CheckSSH = !*noSSH
	opts.CheckTelnet = true
	opts.CheckHTTP = !*noHTTP
	opts.CheckTLS = !*noTLS
	opts.CheckPorts = !*noPorts

	auditor := netaudit.NewAuditor(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted.")
		cancel()
	}()

	fmt.Printf("Auditing %s...\n", target)

	result, err := auditor.Audit(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *brief {
		fmt.Println(result.FormatCompact())
	} else {
		fmt.Print(result.Format())
	}

	// Exit code based on severity
	if result.Summary.Critical > 0 {
		os.Exit(2)
	} else if result.Summary.High > 0 {
		os.Exit(1)
	}
}
