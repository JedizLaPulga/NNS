package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/upnp"
)

func runUPnP(args []string) {
	fs := flag.NewFlagSet("upnp", flag.ExitOnError)
	timeout := fs.Duration("timeout", 3*time.Second, "Discovery timeout")
	target := fs.String("target", "ssdp:all", "Search target (ssdp:all, upnp:rootdevice, etc.)")
	noDetails := fs.Bool("no-details", false, "Skip fetching device details via HTTP")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns upnp [OPTIONS]

Discover UPnP devices on the local network.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
SEARCH TARGETS:
    ssdp:all                                    - All devices (default)
    upnp:rootdevice                             - Root devices only
    urn:schemas-upnp-org:device:InternetGatewayDevice:1  - Routers
    urn:schemas-upnp-org:device:MediaServer:1   - Media servers
    urn:schemas-upnp-org:device:MediaRenderer:1 - Media renderers

EXAMPLES:
    nns upnp
    nns upnp --timeout 5s
    nns upnp --target upnp:rootdevice
    nns upnp --no-details
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	cfg := upnp.Config{
		Timeout:      *timeout,
		SearchTarget: *target,
		FetchDetails: !*noDetails,
	}

	scanner := upnp.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nCancelling...")
		cancel()
	}()

	fmt.Printf("Discovering UPnP devices (target: %s)...\n\n", *target)

	result, err := scanner.Scan(ctx)
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(result.Format())
}
