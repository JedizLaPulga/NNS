package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/JedizLaPulga/NNS/internal/listen"
)

func runListen(args []string) {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	port := fs.Int("p", 8080, "Port to listen on")
	host := fs.String("host", "0.0.0.0", "Host/IP to bind to")
	udp := fs.Bool("udp", false, "Use UDP instead of TCP")
	echo := fs.Bool("echo", false, "Echo received data back to client")
	maxConns := fs.Int("max", 0, "Max concurrent connections (0=unlimited)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns listen [options]\n\n")
		fmt.Fprintf(os.Stderr, "Start a TCP/UDP listener for connectivity testing.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns listen -p 9000\n")
		fmt.Fprintf(os.Stderr, "  nns listen -p 9000 --echo\n")
		fmt.Fprintf(os.Stderr, "  nns listen -p 9000 --udp\n")
		fmt.Fprintf(os.Stderr, "  nns listen --host 127.0.0.1 -p 8080\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	protocol := listen.TCP
	if *udp {
		protocol = listen.UDP
	}

	cfg := listen.Config{
		Port:     *port,
		Host:     *host,
		Protocol: protocol,
		Echo:     *echo,
		MaxConns: *maxConns,
	}

	listener := listen.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
		listener.Stop()
	}()

	fmt.Printf("Listening on %s (%s)", listener.Address(), protocol)
	if *echo {
		fmt.Print(" [ECHO MODE]")
	}
	fmt.Println("\nPress Ctrl+C to stop\n")

	err := listener.Start(ctx, func(e listen.Event) {
		fmt.Println(listen.FormatEvent(e))
	})

	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	stats := listener.GetStats()
	fmt.Printf("\n%s\n", listen.FormatStats(stats))
}
