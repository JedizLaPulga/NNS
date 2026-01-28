package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jedizlapulga/nns/internal/pcap"
)

func runPcap(args []string) {
	fs := flag.NewFlagSet("pcap", flag.ExitOnError)
	iface := fs.String("interface", "", "Network interface to capture on")
	protocol := fs.String("protocol", "", "Filter by protocol (tcp, udp, icmp)")
	port := fs.Int("port", 0, "Filter by port number")
	srcHost := fs.String("src", "", "Filter by source IP")
	dstHost := fs.String("dst", "", "Filter by destination IP")
	count := fs.Int("count", 0, "Max packets to capture (0=unlimited)")
	duration := fs.Duration("duration", 0, "Max capture duration (0=unlimited)")
	listIfaces := fs.Bool("list", false, "List available interfaces")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns pcap [OPTIONS]

Capture and analyze network packets.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
    nns pcap --interface eth0
    nns pcap --interface eth0 --protocol tcp --port 443
    nns pcap --list
    nns pcap --duration 10s --count 100
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	// List interfaces mode
	if *listIfaces {
		ifaces, err := pcap.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing interfaces: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Available network interfaces:")
		for _, i := range ifaces {
			fmt.Printf("  %-20s %s\n", i.Name, i.Flags)
			for _, addr := range i.Addresses {
				fmt.Printf("    %s\n", addr)
			}
		}
		return
	}

	opts := pcap.DefaultOptions()
	opts.Interface = *iface
	opts.Filter.Protocol = *protocol
	opts.Filter.Port = *port
	opts.Filter.SrcHost = *srcHost
	opts.Filter.DstHost = *dstHost
	opts.MaxPackets = *count
	opts.MaxDuration = *duration

	cap, err := pcap.NewCapture(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Set up packet handler
	cap.SetHandler(func(pkt pcap.Packet) {
		fmt.Println(pkt.Format())
	})

	// Handle Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nStopping capture...")
		cap.Stop()
		cancel()
	}()

	fmt.Printf("Capturing on %s...\n", opts.Interface)
	if opts.Filter.Protocol != "" {
		fmt.Printf("Filter: protocol=%s\n", opts.Filter.Protocol)
	}
	if opts.Filter.Port > 0 {
		fmt.Printf("Filter: port=%d\n", opts.Filter.Port)
	}
	fmt.Println("Press Ctrl+C to stop\n")

	if err := cap.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting capture: %v\n", err)
		os.Exit(1)
	}

	// Wait for capture to complete
	for cap.IsRunning() {
		time.Sleep(100 * time.Millisecond)
	}

	// Print stats
	stats := cap.Stats()
	fmt.Println()
	fmt.Print(stats.Format())
}
