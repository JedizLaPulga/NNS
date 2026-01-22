package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/JedizLaPulga/NNS/internal/tcptest"
)

func runTCPTest(args []string) {
	fs := flag.NewFlagSet("tcptest", flag.ExitOnError)
	portFlag := fs.Int("port", 80, "Target port")
	countFlag := fs.Int("count", 4, "Number of tests")
	intervalFlag := fs.Duration("interval", 1*time.Second, "Time between tests")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Connection timeout")
	tlsFlag := fs.Bool("tls", false, "Enable TLS handshake")
	insecureFlag := fs.Bool("insecure", false, "Skip TLS certificate verification")

	// Short flags
	fs.IntVar(portFlag, "p", 80, "Target port")
	fs.IntVar(countFlag, "c", 4, "Number of tests")
	fs.DurationVar(intervalFlag, "i", 1*time.Second, "Time between tests")
	fs.DurationVar(timeoutFlag, "t", 10*time.Second, "Connection timeout")
	fs.BoolVar(tlsFlag, "s", false, "Enable TLS handshake")
	fs.BoolVar(insecureFlag, "k", false, "Skip TLS certificate verification")

	fs.Usage = func() {
		fmt.Println(`Usage: nns tcptest [HOST] [OPTIONS]

Test TCP connectivity with detailed timing breakdown.

OPTIONS:
  --port, -p       Target port (default: 80)
  --count, -c      Number of tests (default: 4)
  --interval, -i   Time between tests (default: 1s)
  --timeout, -t    Connection timeout (default: 10s)
  --tls, -s        Enable TLS handshake
  --insecure, -k   Skip TLS certificate verification
  --help           Show this help message

EXAMPLES:
  nns tcptest google.com
  nns tcptest google.com -p 443 --tls
  nns tcptest example.com -c 10 -i 500ms
  nns tcptest api.example.com -p 443 --tls --insecure`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: target host required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)

	// Auto-enable TLS for port 443
	if *portFlag == 443 && !*tlsFlag {
		*tlsFlag = true
	}

	tester := tcptest.NewTester(host, *portFlag)
	tester.Count = *countFlag
	tester.Interval = *intervalFlag
	tester.Timeout = *timeoutFlag
	tester.UseTLS = *tlsFlag
	tester.SkipVerify = *insecureFlag

	// Print header
	fmt.Printf("TCP Test to %s (port %d)\n", host, *portFlag)
	if tester.UseTLS {
		fmt.Println("TLS: enabled")
	}
	fmt.Printf("Timeout: %v, Count: %d, Interval: %v\n", tester.Timeout, tester.Count, tester.Interval)
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
	err := tester.Run(ctx, func(r tcptest.Result) {
		if r.Success {
			if tester.UseTLS {
				fmt.Printf("seq=%d  dns=%v  conn=%v  tls=%v  total=%v  [%s %s]\n",
					r.Seq, r.DNSTime.Round(time.Microsecond), r.ConnectTime.Round(time.Microsecond),
					r.TLSTime.Round(time.Microsecond), r.TotalTime.Round(time.Microsecond),
					r.TLSVersion, truncateStr(r.TLSCipherName, 30))
			} else {
				fmt.Printf("seq=%d  dns=%v  conn=%v  total=%v  addr=%s\n",
					r.Seq, r.DNSTime.Round(time.Microsecond), r.ConnectTime.Round(time.Microsecond),
					r.TotalTime.Round(time.Microsecond), r.RemoteAddr)
			}
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
	fmt.Printf("\n--- %s:%d TCP test statistics ---\n", host, *portFlag)
	fmt.Printf("%d connections, %d succeeded, %d failed (%.1f%% success)\n",
		stats.Sent, stats.Successful, stats.Failed, stats.SuccessRate)

	if stats.Successful > 0 {
		fmt.Println("\nTiming breakdown:")
		fmt.Printf("  DNS avg:        %v\n", stats.AvgDNSTime.Round(time.Microsecond))
		fmt.Printf("  Connect avg:    %v\n", stats.AvgConnTime.Round(time.Microsecond))
		fmt.Printf("  Total min:      %v\n", stats.MinTime.Round(time.Microsecond))
		fmt.Printf("  Total avg:      %v\n", stats.AvgTime.Round(time.Microsecond))
		fmt.Printf("  Total max:      %v\n", stats.MaxTime.Round(time.Microsecond))
		fmt.Printf("  Total median:   %v\n", stats.MedianTime.Round(time.Microsecond))
		fmt.Printf("  Std dev:        %v\n", stats.StdDev.Round(time.Microsecond))
		fmt.Printf("  95th %%ile:      %v\n", stats.P95.Round(time.Microsecond))
		fmt.Printf("  99th %%ile:      %v\n", stats.P99.Round(time.Microsecond))
		fmt.Printf("\nConnection Quality: %s\n", stats.Quality())
	}
}

// truncateStr truncates a string to maxLen, adding "..." if needed.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
