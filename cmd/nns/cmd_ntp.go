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

	"github.com/JedizLaPulga/NNS/internal/ntp"
)

func runNTP(args []string) {
	fs := flag.NewFlagSet("ntp", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "Query timeout")
	server := fs.String("server", "", "Specific NTP server to query")
	all := fs.Bool("all", false, "Test all known public NTP servers")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns ntp [OPTIONS] [server]

Check NTP servers and analyze time offset.

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
    nns ntp
    nns ntp --all
    nns ntp pool.ntp.org
    nns ntp time.google.com --timeout 10s
`)
	}

	if err := fs.Parse(args); err != nil {
		return
	}

	cfg := ntp.Config{
		Timeout: *timeout,
	}

	// Determine which servers to test
	if fs.NArg() > 0 {
		serverAddr := fs.Arg(0)
		if !strings.Contains(serverAddr, ":") {
			serverAddr = serverAddr + ":123"
		}
		cfg.Servers = []ntp.Server{{Name: fs.Arg(0), Address: serverAddr}}
	} else if *server != "" {
		serverAddr := *server
		if !strings.Contains(serverAddr, ":") {
			serverAddr = *server + ":123"
		}
		cfg.Servers = []ntp.Server{{Name: *server, Address: serverAddr}}
	} else if *all {
		cfg.Servers = ntp.PublicServers
	} else {
		cfg.Servers = ntp.PublicServers[:4]
	}

	checker := ntp.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nCancelling...")
		cancel()
	}()

	serverNames := make([]string, len(cfg.Servers))
	for i, s := range cfg.Servers {
		serverNames[i] = s.Name
	}

	fmt.Printf("Checking NTP servers: %s\n\n", strings.Join(serverNames, ", "))

	result := checker.CheckAll(ctx)
	fmt.Print(result.Format())
}
