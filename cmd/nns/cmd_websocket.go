package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/JedizLaPulga/NNS/internal/websocket"
)

func runWebSocket(args []string) {
	fs := flag.NewFlagSet("websocket", flag.ExitOnError)
	countFlag := fs.Int("count", 4, "Number of tests")
	intervalFlag := fs.Duration("interval", 1*time.Second, "Time between tests")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Connection timeout")
	insecureFlag := fs.Bool("insecure", false, "Skip TLS certificate verification")
	sizeFlag := fs.Int("size", 32, "Message size in bytes")
	protocolFlag := fs.String("protocol", "", "WebSocket sub-protocol")
	originFlag := fs.String("origin", "", "Custom origin header")

	// Short flags
	fs.IntVar(countFlag, "c", 4, "Number of tests")
	fs.DurationVar(intervalFlag, "i", 1*time.Second, "Time between tests")
	fs.DurationVar(timeoutFlag, "t", 10*time.Second, "Connection timeout")
	fs.BoolVar(insecureFlag, "k", false, "Skip TLS certificate verification")
	fs.IntVar(sizeFlag, "s", 32, "Message size in bytes")

	fs.Usage = func() {
		fmt.Println(`Usage: nns websocket [URL] [OPTIONS]

Test WebSocket connectivity and measure latency.

OPTIONS:
  --count, -c      Number of tests (default: 4)
  --interval, -i   Time between tests (default: 1s)
  --timeout, -t    Connection timeout (default: 10s)
  --insecure, -k   Skip TLS certificate verification
  --size, -s       Message size in bytes (default: 32)
  --protocol       WebSocket sub-protocol to request
  --origin         Custom origin header
  --help           Show this help message

EXAMPLES:
  nns websocket ws://echo.websocket.org
  nns websocket wss://example.com/socket -c 10
  nns websocket ws://localhost:8080/ws --protocol json`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: WebSocket URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	url := fs.Arg(0)

	tester := websocket.NewTester(url)
	tester.Count = *countFlag
	tester.Interval = *intervalFlag
	tester.Timeout = *timeoutFlag
	tester.SkipVerify = *insecureFlag
	tester.MessageSize = *sizeFlag
	if *protocolFlag != "" {
		tester.Protocol = *protocolFlag
	}
	if *originFlag != "" {
		tester.Origin = *originFlag
	}

	// Print header
	fmt.Printf("WebSocket Test to %s\n", url)
	fmt.Printf("Timeout: %v, Count: %d, Interval: %v, Message size: %d bytes\n",
		tester.Timeout, tester.Count, tester.Interval, tester.MessageSize)
	if tester.Protocol != "" {
		fmt.Printf("Sub-protocol: %s\n", tester.Protocol)
	}
	fmt.Println()

	// Handle Ctrl+C gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, calculating statistics...")
		cancel()
	}()

	// Run tests
	err := tester.Run(ctx, func(r websocket.Result) {
		if r.Success {
			fmt.Printf("seq=%d  connect=%v  rtt=%v  total=%v",
				r.Seq, r.ConnectTime.Round(time.Microsecond),
				r.RoundTripTime.Round(time.Microsecond),
				r.TotalTime.Round(time.Microsecond))
			if r.Protocol != "" {
				fmt.Printf("  proto=%s", r.Protocol)
			}
			fmt.Println()
		} else {
			fmt.Printf("seq=%d  FAILED: %v\n", r.Seq, r.Error)
		}
	})

	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}

	// Print statistics
	stats := tester.Stats
	fmt.Printf("\n--- %s WebSocket test statistics ---\n", url)
	fmt.Printf("%d tests, %d succeeded, %d failed (%.1f%% success)\n",
		stats.Sent, stats.Successful, stats.Failed, stats.SuccessRate)

	if stats.Successful > 0 {
		fmt.Println("\nRound-trip time:")
		fmt.Printf("  min:      %v\n", stats.MinRTT.Round(time.Microsecond))
		fmt.Printf("  avg:      %v\n", stats.AvgRTT.Round(time.Microsecond))
		fmt.Printf("  max:      %v\n", stats.MaxRTT.Round(time.Microsecond))
		fmt.Printf("  median:   %v\n", stats.MedianRTT.Round(time.Microsecond))
		fmt.Printf("  stddev:   %v\n", stats.StdDev.Round(time.Microsecond))
		fmt.Printf("  jitter:   %v\n", stats.Jitter.Round(time.Microsecond))
		fmt.Printf("  95th %%:   %v\n", stats.P95.Round(time.Microsecond))
		fmt.Printf("  99th %%:   %v\n", stats.P99.Round(time.Microsecond))
		fmt.Printf("\nConnection Quality: %s\n", stats.Quality())
	}
}
