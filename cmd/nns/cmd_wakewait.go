package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/wakewait"
)

func runWakeWait(args []string) {
	fs := flag.NewFlagSet("wakewait", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Minute, "Max time to wait for host")
	port := fs.Int("port", 22, "TCP port to check for connectivity")
	interval := fs.Duration("interval", 2*time.Second, "Check interval")
	broadcast := fs.String("broadcast", "255.255.255.255", "Broadcast address for WoL")
	retries := fs.Int("retries", 3, "Number of WoL packet retries")
	nowait := fs.Bool("nowait", false, "Send WoL and exit immediately (don't wait)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns wakewait [options] <mac> [ip]\n\n")
		fmt.Fprintf(os.Stderr, "Send Wake-on-LAN packet and wait for host to come online.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns wakewait AA:BB:CC:DD:EE:FF 192.168.1.100\n")
		fmt.Fprintf(os.Stderr, "  nns wakewait --port 3389 AA:BB:CC:DD:EE:FF 192.168.1.100\n")
		fmt.Fprintf(os.Stderr, "  nns wakewait --nowait AA:BB:CC:DD:EE:FF\n")
		fmt.Fprintf(os.Stderr, "  nns wakewait --timeout 10m AA:BB:CC:DD:EE:FF 192.168.1.100\n")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	mac := fs.Arg(0)
	ip := fs.Arg(1)

	// Validate MAC
	if _, err := wakewait.ParseMAC(mac); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid MAC address: %v\n", err)
		os.Exit(1)
	}

	// Quick wake mode
	if *nowait {
		fmt.Printf("⚡ Sending Wake-on-LAN to %s...\n", mac)
		if err := wakewait.QuickWake(mac, *broadcast); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Magic packet sent successfully")
		return
	}

	// Need IP for wait mode
	if ip == "" {
		fmt.Fprintf(os.Stderr, "Error: IP address required for wait mode (use --nowait for fire-and-forget)\n")
		os.Exit(1)
	}

	cfg := wakewait.DefaultConfig()
	cfg.Timeout = *timeout
	cfg.TCPPort = *port
	cfg.CheckInterval = *interval
	cfg.BroadcastAddr = *broadcast
	cfg.RetryWol = *retries

	client := wakewait.NewClient(cfg)

	// Status updates
	client.OnEvent(func(r wakewait.Result) {
		switch r.Status {
		case wakewait.StatusWaking:
			fmt.Printf("⚡ [%s] WoL packet #%d sent, waiting for %s:%d...\n",
				time.Now().Format("15:04:05"), r.Attempts, ip, *port)
		case wakewait.StatusOnline:
			fmt.Printf("✓ [%s] Host is ONLINE! Wake time: %v\n",
				r.OnlineAt.Format("15:04:05"), r.WakeTime.Round(time.Millisecond))
		case wakewait.StatusTimeout:
			fmt.Printf("✗ [%s] Timeout after %v\n", time.Now().Format("15:04:05"), *timeout)
		}
	})

	// Handle Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n⚠ Interrupted")
		cancel()
	}()

	fmt.Printf("\n🔌 Wake and Wait\n")
	fmt.Printf("   MAC:       %s\n", mac)
	fmt.Printf("   Target:    %s:%d\n", ip, *port)
	fmt.Printf("   Timeout:   %v\n", *timeout)
	fmt.Printf("   Broadcast: %s\n\n", *broadcast)

	result, err := client.WakeAndWait(ctx, mac, ip)

	if err != nil {
		if result != nil && result.Status == wakewait.StatusTimeout {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	printWakeWaitSummary(result)
}

func printWakeWaitSummary(r *wakewait.Result) {
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║           Wake-on-LAN Summary          ║")
	fmt.Println("╠════════════════════════════════════════╣")
	fmt.Printf("║  MAC Address:    %-21s ║\n", r.MAC)
	fmt.Printf("║  Target IP:      %-21s ║\n", r.IP)
	fmt.Printf("║  Status:         %-21s ║\n", r.Status)
	fmt.Printf("║  WoL Attempts:   %-21d ║\n", r.Attempts)
	fmt.Printf("║  WoL Sent:       %-21s ║\n", r.WolSentAt.Format("15:04:05"))
	if r.Status == wakewait.StatusOnline {
		fmt.Printf("║  Online At:      %-21s ║\n", r.OnlineAt.Format("15:04:05"))
		fmt.Printf("║  Wake Time:      %-21v ║\n", r.WakeTime.Round(time.Millisecond))
	}
	fmt.Println("╚════════════════════════════════════════╝")
}
