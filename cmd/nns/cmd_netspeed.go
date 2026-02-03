package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/netspeed"
)

func runNetspeed(args []string) {
	fs := flag.NewFlagSet("netspeed", flag.ExitOnError)
	serverMode := fs.Bool("server", false, "Run in server mode")
	port := fs.Int("port", 5201, "Port for server/client")
	duration := fs.Duration("duration", 10*time.Second, "Test duration")
	connections := fs.Int("connections", 1, "Number of parallel connections")
	bidirectional := fs.Bool("bidir", false, "Bidirectional test")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns netspeed [OPTIONS] [host]

Internal network speed test (iperf-like).

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
MODES:
    Server: nns netspeed --server
    Client: nns netspeed <server-ip>

EXAMPLES:
    # Start server on default port
    nns netspeed --server
    
    # Start server on custom port
    nns netspeed --server --port 5200
    
    # Run client test
    nns netspeed 192.168.1.100
    
    # Run with multiple connections
    nns netspeed 192.168.1.100 --connections 4
    
    # Run bidirectional test
    nns netspeed 192.168.1.100 --bidir
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nStopping...")
		cancel()
	}()

	if *serverMode {
		// Server mode
		cfg := netspeed.Config{
			Port:          *port,
			Bidirectional: *bidirectional,
		}
		server := netspeed.NewServer(cfg)

		err := server.Start(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Speed test server listening on %s\n", server.Address())
		fmt.Println("Press Ctrl+C to stop")
		fmt.Println()

		// Wait for cancellation
		<-ctx.Done()

		stats := server.GetStats()
		fmt.Printf("\nServer statistics:\n")
		fmt.Printf("  Total connections: %d\n", stats.TotalConnections)
		fmt.Printf("  Total data: %s\n", formatBytesSimple(stats.TotalBytes))

		server.Stop()
	} else {
		// Client mode
		if fs.NArg() < 1 {
			fs.Usage()
			os.Exit(1)
		}

		host := fs.Arg(0)

		cfg := netspeed.Config{
			Port:          *port,
			Duration:      *duration,
			Connections:   *connections,
			Bidirectional: *bidirectional,
		}
		client := netspeed.NewClient(cfg)

		fmt.Printf("Connecting to %s:%d...\n", host, *port)
		fmt.Printf("Duration: %v, Connections: %d\n\n", *duration, *connections)

		result, err := client.Test(ctx, host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Print(result.Format())
	}
}

func formatBytesSimple(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
