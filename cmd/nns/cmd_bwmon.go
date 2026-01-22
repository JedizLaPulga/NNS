package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/bwmon"
)

func runBWMon(args []string) {
	fs := flag.NewFlagSet("bwmon", flag.ExitOnError)
	intervalFlag := fs.Duration("interval", 1*time.Second, "Update interval")
	activeFlag := fs.Bool("active", false, "Only show interfaces with traffic")
	countFlag := fs.Int("count", 0, "Number of updates (0 = infinite)")
	simulateFlag := fs.Bool("simulate", false, "Use simulated data for demo")
	compactFlag := fs.Bool("compact", false, "Compact single-line output")

	// Short flags
	fs.DurationVar(intervalFlag, "i", 1*time.Second, "Update interval")
	fs.BoolVar(activeFlag, "a", false, "Only show interfaces with traffic")
	fs.IntVar(countFlag, "c", 0, "Number of updates")
	fs.BoolVar(simulateFlag, "s", false, "Simulate data")

	fs.Usage = func() {
		fmt.Println(`Usage: nns bwmon [OPTIONS]

Real-time bandwidth monitoring for network interfaces.

OPTIONS:
  --interval, -i   Update interval (default: 1s)
  --active, -a     Only show interfaces with traffic
  --count, -c      Number of updates (0 = infinite)
  --simulate, -s   Use simulated data for demo
  --compact        Compact single-line output
  --help           Show this help message

EXAMPLES:
  nns bwmon
  nns bwmon -i 2s
  nns bwmon --active
  nns bwmon --simulate -c 10`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	monitor := bwmon.NewMonitor()
	monitor.Interval = *intervalFlag
	monitor.FilterActive = *activeFlag

	// Handle Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nStopping bandwidth monitor...")
		cancel()
	}()

	fmt.Println("Bandwidth Monitor")
	fmt.Printf("Interval: %v", monitor.Interval)
	if *simulateFlag {
		fmt.Print(" (simulated)")
	}
	fmt.Println()
	fmt.Println(strings.Repeat("─", 70))

	iteration := 0
	ticker := time.NewTicker(monitor.Interval)
	defer ticker.Stop()

	// Track max values for bar scaling
	var maxRx, maxTx float64 = 1024, 1024 // Start with 1 KB/s minimum

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			iteration++

			var stats []bwmon.InterfaceStats
			var err error

			if *simulateFlag {
				stats = bwmon.SimulatedStats(iteration)
			} else {
				stats, err = monitor.GetStats()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error getting stats: %v\n", err)
					fmt.Println("Tip: Use --simulate for a demo on unsupported platforms")
					os.Exit(1)
				}
			}

			rates := monitor.CalculateRates(stats)

			// Update max values for scaling
			for _, r := range rates {
				if r.RxBytesPerSec > maxRx {
					maxRx = r.RxBytesPerSec
				}
				if r.TxBytesPerSec > maxTx {
					maxTx = r.TxBytesPerSec
				}
			}

			// Clear screen for updates (keep header visible)
			if iteration > 1 && !*compactFlag {
				// Move cursor up and clear lines
				for i := 0; i < len(rates)+2; i++ {
					fmt.Print("\033[A\033[K")
				}
			}

			if *compactFlag {
				printCompactRates(rates, iteration)
			} else {
				printDetailedRates(rates, maxRx, maxTx)
			}

			if *countFlag > 0 && iteration >= *countFlag {
				fmt.Println("\nDone.")
				return
			}
		}
	}
}

func printDetailedRates(rates []bwmon.BandwidthRate, maxRx, maxTx float64) {
	fmt.Printf("%-12s %15s %15s %10s %10s\n", "INTERFACE", "RX/s", "TX/s", "RX Total", "TX Total")
	fmt.Println(strings.Repeat("─", 70))

	for _, r := range rates {
		rxBar := bwmon.RenderBar(r.RxBytesPerSec, maxRx, 8)
		txBar := bwmon.RenderBar(r.TxBytesPerSec, maxTx, 8)

		fmt.Printf("%-12s %8s %s %8s %s %10s %10s\n",
			truncateName(r.Name, 12),
			bwmon.FormatBytesPerSec(r.RxBytesPerSec),
			rxBar,
			bwmon.FormatBytesPerSec(r.TxBytesPerSec),
			txBar,
			bwmon.FormatBytes(r.TotalRxBytes),
			bwmon.FormatBytes(r.TotalTxBytes),
		)
	}

	if len(rates) == 0 {
		fmt.Println("  No active interfaces found")
	}
}

func printCompactRates(rates []bwmon.BandwidthRate, iteration int) {
	timestamp := time.Now().Format("15:04:05")
	var parts []string

	for _, r := range rates {
		parts = append(parts, fmt.Sprintf("%s[↓%s ↑%s]",
			truncateName(r.Name, 6),
			bwmon.FormatBytesPerSec(r.RxBytesPerSec),
			bwmon.FormatBytesPerSec(r.TxBytesPerSec),
		))
	}

	fmt.Printf("[%s] %s\n", timestamp, strings.Join(parts, " "))
}

// truncateName truncates interface name if too long.
func truncateName(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name
	}
	return name[:maxLen-1] + "…"
}
