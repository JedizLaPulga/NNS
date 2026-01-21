package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/netwatch"
)

func runNetwatch(args []string) {
	fs := flag.NewFlagSet("netwatch", flag.ExitOnError)

	intervalFlag := fs.Duration("interval", 5*time.Second, "Poll interval")
	hostFlag := fs.String("host", "", "Additional host to monitor")
	durationFlag := fs.Duration("duration", 0, "How long to monitor (0 = until Ctrl+C)")

	fs.DurationVar(intervalFlag, "i", 5*time.Second, "Poll interval")
	fs.StringVar(hostFlag, "H", "", "Host to monitor")
	fs.DurationVar(durationFlag, "d", 0, "Duration")

	fs.Usage = func() {
		fmt.Println(`Usage: nns netwatch [OPTIONS]

Monitor network changes in real-time (interface up/down, address changes, connectivity).

OPTIONS:
  -i, --interval    Poll interval (default: 5s)
  -H, --host        Additional host to monitor
  -d, --duration    How long to monitor (0 = until Ctrl+C)
  --help            Show this help message

EXAMPLES:
  nns netwatch
  nns netwatch --interval 10s --host google.com
  nns netwatch --duration 5m`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg := netwatch.Config{
		PollInterval:          *intervalFlag,
		ConnectivityCheckHost: "8.8.8.8",
		LatencyThreshold:      500 * time.Millisecond,
	}

	if *hostFlag != "" {
		cfg.MonitoredHosts = []string{*hostFlag}
	}

	watcher := netwatch.NewWatcher(cfg)

	ctx := context.Background()
	if *durationFlag > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *durationFlag)
		defer cancel()
	}

	fmt.Printf("Watching for network changes (poll interval: %v)...\n", cfg.PollInterval)
	fmt.Println("Press Ctrl+C to stop.")

	// Show initial state
	ifaces, hosts, connected := watcher.GetCurrentState()
	fmt.Printf("Initial state: %d interfaces, connectivity: %v\n", len(ifaces), connected)
	for host, state := range hosts {
		status := "unreachable"
		if state.IsReachable {
			status = "reachable"
		}
		fmt.Printf("  - %s: %s\n", host, status)
	}
	fmt.Println()

	events := watcher.Watch(ctx)

	for event := range events {
		fmt.Println(netwatch.FormatEvent(event))
	}

	fmt.Println("\nNetwatch stopped.")
}
