package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/traceroute"
)

func runTraceroute(args []string) {
	fs := flag.NewFlagSet("traceroute", flag.ExitOnError)

	maxHopsFlag := fs.Int("max-hops", 30, "Maximum hops")
	queriesFlag := fs.Int("queries", 3, "Probes per hop")
	timeoutFlag := fs.Duration("timeout", 2*time.Second, "Timeout per hop")
	asFlag := fs.Bool("as", true, "Resolve AS number")

	// Short flags
	fs.IntVar(maxHopsFlag, "m", 30, "Maximum hops")
	fs.IntVar(queriesFlag, "q", 3, "Probes per hop")
	fs.BoolVar(asFlag, "a", true, "Resolve AS number")

	fs.Usage = func() {
		fmt.Println(`Usage: nns traceroute [OPTIONS] [HOST]

Trace route to a destination host.

OPTIONS:
  -m, --max-hops    Maximum hops (default: 30)
  -q, --queries     Probes per hop (default: 3)
  --timeout         Timeout per hop (default: 2s)
  -a, --as          Resolve AS numbers (default: true)
  --help            Show this help message

> **Windows Note**: You may need to allow "File and Printer Sharing (Echo Request - ICMPv4-In)" and "ICMPv4 Time Exceeded" in Windows Firewall to receive replies.

EXAMPLES:
  nns traceroute google.com
  nns traceroute -m 64 example.com`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: host required\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)

	cfg := traceroute.Config{
		Target:    host,
		MaxHops:   *maxHopsFlag,
		Queries:   *queriesFlag,
		Timeout:   *timeoutFlag,
		ResolveAS: *asFlag,
	}

	tracer := traceroute.NewTracer(cfg)

	fmt.Printf("Traceroute to %s, %d hops max\n", host, cfg.MaxHops)
	fmt.Printf("%-3s %-16s %-30s %-20s %s\n", "HOP", "IP", "HOST", "AS/ORG", "RTT")
	fmt.Println("------------------------------------------------------------------------------------------")

	err := tracer.Run(context.Background(), func(h *traceroute.Hop) {
		if h.Timeout {
			fmt.Printf("%-3d *                *                              *                    *\n", h.TTL)
			return
		}

		hostStr := ""
		if len(h.Hosts) > 0 {
			hostStr = h.Hosts[0]
			if len(hostStr) > 28 {
				hostStr = hostStr[:25] + "..."
			}
		} else {
			hostStr = "(" + h.IP + ")"
		}

		asStr := ""
		if h.ASN != "" {
			asStr = fmt.Sprintf("[%s] %s", h.ASN, h.Org)
			if len(asStr) > 19 {
				asStr = asStr[:16] + "..."
			}
		}

		// RTTs
		rttStr := ""
		for _, rtt := range h.RTTs {
			rttStr += fmt.Sprintf("%.1fms ", float64(rtt.Microseconds())/1000.0)
		}
		if len(h.RTTs) < cfg.Queries {
			for i := 0; i < cfg.Queries-len(h.RTTs); i++ {
				rttStr += "* "
			}
		}

		fmt.Printf("%-3d %-16s %-30s %-20s %s\n",
			h.TTL, h.IP, hostStr, asStr, rttStr)
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}
}
