package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/leak"
)

func runLeak(args []string) {
	fs := flag.NewFlagSet("leak", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "Test timeout")
	vpnExpected := fs.Bool("vpn", false, "Expect VPN connection (warn if not detected)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns leak [OPTIONS]

Test for DNS and IP leaks (VPN privacy audit).

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
DESCRIPTION:
    This command tests your connection for potential privacy leaks:
    
    • DNS Leaks: Checks if your DNS queries are going through multiple
      providers, which could reveal your browsing activity.
    
    • IP Leaks: Identifies your public IP and checks if it appears to
      be from a VPN provider or your real ISP.

EXAMPLES:
    nns leak
    nns leak --vpn          # Warn if VPN not detected
    nns leak --timeout 15s
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	cfg := leak.Config{
		Timeout:     *timeout,
		VPNExpected: *vpnExpected,
	}

	tester := leak.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nCancelling...")
		cancel()
	}()

	fmt.Println("Running DNS/IP leak test...")
	if *vpnExpected {
		fmt.Println("VPN mode: Will warn if VPN not detected")
	}
	fmt.Println()

	result, err := tester.TestAll(ctx)
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(result.Format())
}
