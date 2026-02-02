package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/fingerprint"
)

func runFingerprint(args []string) {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "Connection timeout")
	ports := fs.String("ports", "", "Ports to scan (comma-separated, default: common ports)")
	osOnly := fs.Bool("os-only", false, "Only perform OS detection")
	servicesOnly := fs.Bool("services-only", false, "Only perform service detection")
	brief := fs.Bool("brief", false, "Brief output")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns fingerprint [options] <host>\n\n")
		fmt.Fprintf(os.Stderr, "Fingerprint remote host for OS and service detection.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns fingerprint example.com\n")
		fmt.Fprintf(os.Stderr, "  nns fingerprint --ports 22,80,443 192.168.1.1\n")
		fmt.Fprintf(os.Stderr, "  nns fingerprint --os-only 10.0.0.1\n")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)

	opts := fingerprint.DefaultOptions()
	opts.Timeout = *timeout

	if *ports != "" {
		opts.Ports = parseFingerPorts(*ports)
	}

	if *osOnly {
		opts.ServiceScan = false
	}
	if *servicesOnly {
		opts.OSDetect = false
	}

	scanner := fingerprint.NewScanner(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n⚠ Interrupted")
		cancel()
	}()

	fmt.Printf("Fingerprinting %s (%d ports)...\n", host, len(opts.Ports))

	result, err := scanner.Scan(ctx, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *brief {
		printFingerprintBrief(result)
	} else {
		fmt.Print(result.Format())
	}
}

func parseFingerPorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Handle ranges
		if strings.Contains(p, "-") {
			parts := strings.Split(p, "-")
			if len(parts) == 2 {
				start, _ := strconv.Atoi(parts[0])
				end, _ := strconv.Atoi(parts[1])
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
				continue
			}
		}
		port, err := strconv.Atoi(p)
		if err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}

func printFingerprintBrief(result *fingerprint.FingerprintResult) {
	fmt.Printf("\n%s\n", result.Host)
	fmt.Printf("  OS:       %s %s [%s confidence]\n", result.OSFamily, result.OSVersion, result.OSConfidence)
	fmt.Printf("  TTL:      %d (%s)\n", result.TTL, result.TTLGuess)
	fmt.Printf("  Open:     %v\n", result.OpenPorts)

	if len(result.Services) > 0 {
		fmt.Printf("  Services:\n")
		for _, svc := range result.Services {
			info := svc.Service
			if svc.Product != "" {
				info += " (" + svc.Product
				if svc.Version != "" {
					info += " " + svc.Version
				}
				info += ")"
			}
			fmt.Printf("    %d: %s\n", svc.Port, info)
		}
	}
	fmt.Printf("  Time:     %v\n", result.Duration.Round(time.Millisecond))
}
