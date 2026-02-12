package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/neighbors"
)

func runNeighbors(args []string) {
	fs := flag.NewFlagSet("neighbors", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "Discovery timeout")
	iface := fs.String("iface", "", "Network interface to use")
	services := fs.String("services", "", "Comma-separated service types to query")
	brief := fs.Bool("brief", false, "Brief output")

	// Short flags
	fs.DurationVar(timeout, "t", 5*time.Second, "Discovery timeout")
	fs.StringVar(iface, "i", "", "Network interface")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns neighbors [options]

Discover network neighbors via mDNS/DNS-SD (Bonjour).
Finds local devices advertising services on the network.

Built-in service types:
  HTTP, HTTPS, SSH, SMB, FTP, Printer, AirPlay,
  Chromecast, Spotify, HomeKit, MQTT, and more.

Options:
  --timeout, -t    Discovery timeout (default: 5s)
  --iface, -i      Network interface to use
  --services       Comma-separated service types to query
                   (e.g. _http._tcp.local.,_ssh._tcp.local.)
  --brief          Brief output
  --help           Show this help message

Examples:
  nns neighbors
  nns neighbors -t 10s
  nns neighbors -i eth0
  nns neighbors --services _http._tcp.local.,_ssh._tcp.local.
  nns neighbors --brief
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := neighbors.DefaultOptions()
	opts.Timeout = *timeout
	opts.Interface = *iface

	if *services != "" {
		types := strings.Split(*services, ",")
		cleaned := make([]string, 0, len(types))
		for _, t := range types {
			t = strings.TrimSpace(t)
			if t != "" {
				cleaned = append(cleaned, t)
			}
		}
		opts.ServiceTypes = cleaned
	}

	scanner := neighbors.NewScanner(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nStopping discovery...")
		cancel()
	}()

	fmt.Printf("Discovering neighbors via mDNS/DNS-SD (timeout: %v)...\n", *timeout)

	result, err := scanner.Discover(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *brief {
		fmt.Println(result.FormatCompact())
	} else {
		fmt.Print(result.Format())
	}
}
