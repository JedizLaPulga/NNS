package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/portknock"
)

func runPortKnock(args []string) {
	fs := flag.NewFlagSet("portknock", flag.ExitOnError)
	delay := fs.Duration("delay", 500*time.Millisecond, "Delay between knocks")
	timeout := fs.Duration("timeout", 2*time.Second, "Timeout per knock")
	proto := fs.String("proto", "tcp", "Protocol: tcp, udp")
	verify := fs.Int("verify", 0, "Port to verify after knocking")

	// Short flags
	fs.DurationVar(delay, "d", 500*time.Millisecond, "Delay between knocks")
	fs.DurationVar(timeout, "t", 2*time.Second, "Timeout per knock")
	fs.StringVar(proto, "P", "tcp", "Protocol: tcp, udp")
	fs.IntVar(verify, "v", 0, "Port to verify after knocking")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns portknock [options] <host> <port1,port2,port3,...>

Send a TCP/UDP port knock sequence to trigger firewall rules.
Port knocking is a security technique where a specific sequence of
connection attempts opens a firewall port.

Options:
  --delay, -d      Delay between knocks (default: 500ms)
  --timeout, -t    Timeout per knock attempt (default: 2s)
  --proto, -P      Protocol: tcp, udp (default: tcp)
  --verify, -v     Port to verify after knocking (default: none)
  --help           Show this help message

Examples:
  nns portknock 192.168.1.1 7000,8000,9000
  nns portknock 192.168.1.1 7000,8000,9000 --verify 22
  nns portknock host.example.com 1234,5678 --delay 1s
  nns portknock 10.0.0.1 100,200,300 --proto udp
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "Error: host and port sequence required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)
	portStr := fs.Arg(1)

	// Parse ports
	portStrs := strings.Split(portStr, ",")
	ports := make([]int, 0, len(portStrs))
	for _, ps := range portStrs {
		ps = strings.TrimSpace(ps)
		p, err := strconv.Atoi(ps)
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintf(os.Stderr, "Error: invalid port %q\n", ps)
			os.Exit(1)
		}
		ports = append(ports, p)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted.")
		cancel()
	}()

	opts := portknock.Options{
		Host:     host,
		Ports:    ports,
		Delay:    *delay,
		Timeout:  *timeout,
		Protocol: *proto,
		Verify:   *verify,
	}

	fmt.Printf("PORT KNOCK %s via %s\n", host, *proto)
	fmt.Printf("Sequence: %s  Delay: %v\n\n", portStr, *delay)

	result, err := portknock.Knock(ctx, opts)
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(portknock.FormatResult(result))
}
