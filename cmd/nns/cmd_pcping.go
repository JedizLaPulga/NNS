package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/JedizLaPulga/NNS/internal/pcping"
)

func runPCPing(args []string) {
	fs := flag.NewFlagSet("pcping", flag.ExitOnError)
	port := fs.Int("port", 0, "Target port (default: auto by protocol)")
	proto := fs.String("proto", "tcp", "Protocol: tcp, udp, http, dns")
	count := fs.Int("count", 5, "Number of probes")
	interval := fs.Duration("interval", 1*time.Second, "Time between probes")
	timeout := fs.Duration("timeout", 5*time.Second, "Probe timeout")
	useTLS := fs.Bool("tls", false, "Use TLS (for TCP/HTTP probes)")
	httpPath := fs.String("path", "/", "HTTP path to probe")

	// Short flags
	fs.IntVar(port, "p", 0, "Target port")
	fs.StringVar(proto, "P", "tcp", "Protocol: tcp, udp, http, dns")
	fs.IntVar(count, "c", 5, "Number of probes")
	fs.DurationVar(interval, "i", 1*time.Second, "Time between probes")
	fs.DurationVar(timeout, "t", 5*time.Second, "Probe timeout")
	fs.BoolVar(useTLS, "s", false, "Use TLS")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns pcping [options] <host>

Protocol-aware ping — probe hosts via TCP, UDP, HTTP, or DNS.
Useful when ICMP ping is blocked by firewalls.

Protocols:
  tcp    TCP connect probe (default)
  udp    UDP probe with response detection
  http   HTTP GET request probe
  dns    DNS query probe

Options:
  --proto, -P       Protocol: tcp, udp, http, dns (default: tcp)
  --port, -p        Target port (default: auto by protocol)
  --count, -c       Number of probes (default: 5)
  --interval, -i    Time between probes (default: 1s)
  --timeout, -t     Probe timeout (default: 5s)
  --tls, -s         Use TLS (for TCP/HTTP probes)
  --path            HTTP path to probe (default: /)
  --help            Show this help message

Examples:
  nns pcping google.com                     # TCP ping port 80
  nns pcping google.com -p 443 --tls        # TCP+TLS ping
  nns pcping google.com -P http             # HTTP ping
  nns pcping 8.8.8.8 -P dns                # DNS ping
  nns pcping example.com -P udp -p 53      # UDP ping
  nns pcping api.example.com -P http --path /health
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: target host required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)

	protocol := pcping.Protocol(*proto)
	switch protocol {
	case pcping.ProtoTCP, pcping.ProtoUDP, pcping.ProtoHTTP, pcping.ProtoDNS:
		// valid
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported protocol %q (use tcp, udp, http, dns)\n", *proto)
		os.Exit(1)
	}

	opts := pcping.Options{
		Host:     host,
		Port:     *port,
		Protocol: protocol,
		Count:    *count,
		Interval: *interval,
		Timeout:  *timeout,
		UseTLS:   *useTLS,
		HTTPPath: *httpPath,
	}

	pinger := pcping.NewPinger(opts)

	fmt.Printf("PCPING %s via %s (port %d)\n", host, protocol, pinger.Port())
	fmt.Printf("Count: %d, Interval: %v, Timeout: %v\n\n", *count, *interval, *timeout)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nInterrupted, calculating statistics...")
		cancel()
	}()

	err := pinger.Run(ctx, func(r pcping.ProbeResult) {
		if r.Success {
			detail := ""
			if r.Detail != "" {
				detail = fmt.Sprintf("  [%s]", r.Detail)
			}
			fmt.Printf("seq=%d  proto=%s  rtt=%v  addr=%s%s\n",
				r.Seq, r.Protocol, r.RTT.Round(time.Microsecond), r.Addr, detail)
		} else {
			fmt.Printf("seq=%d  proto=%s  FAILED: %v\n", r.Seq, r.Protocol, r.Error)
		}
	})

	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(pinger.Stats.Format(host))
}
