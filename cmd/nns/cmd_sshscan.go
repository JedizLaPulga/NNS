package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jedizlapulga/nns/internal/sshscan"
)

func runSSHScan(args []string) {
	fs := flag.NewFlagSet("sshscan", flag.ExitOnError)
	port := fs.Int("port", 22, "SSH port")
	timeout := fs.Duration("timeout", 10*time.Second, "Connection timeout")
	vulnsOnly := fs.Bool("vulns", false, "Show only vulnerabilities")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns sshscan [OPTIONS] <host>

SSH server fingerprinting and security audit.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
    nns sshscan server.example.com
    nns sshscan 192.168.1.1 --port 2222
    nns sshscan server.example.com --vulns
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)

	opts := sshscan.Options{
		Port:    *port,
		Timeout: *timeout,
	}

	scanner := sshscan.NewScanner(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nCancelling...")
		cancel()
	}()

	fmt.Printf("Scanning SSH server %s:%d...\n\n", host, *port)

	result, err := scanner.Scan(ctx, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *vulnsOnly {
		fmt.Printf("SSH Security Audit: %s:%d\n", host, *port)
		fmt.Printf("Grade: %s (%d/100)\n\n", result.Grade, result.Score)

		if len(result.Vulnerabilities) == 0 {
			fmt.Println("✓ No vulnerabilities detected")
		} else {
			vulns := result.GetVulnerabilitiesBySeverity()
			for _, v := range vulns {
				icon := "○"
				switch v.Severity {
				case "critical":
					icon = "✗"
				case "high":
					icon = "!"
				case "medium":
					icon = "△"
				}
				fmt.Printf("%s [%s] %s\n", icon, v.Severity, v.Title)
				fmt.Printf("  %s\n", v.Description)
				fmt.Printf("  Fix: %s\n\n", v.Remediation)
			}
		}
	} else {
		fmt.Print(result.Format())
	}
}
