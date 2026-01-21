package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/mtr"
)

func runMTR(args []string) {
	fs := flag.NewFlagSet("mtr", flag.ExitOnError)

	countFlag := fs.Int("count", 10, "Number of cycles to run")
	maxHopsFlag := fs.Int("max-hops", 30, "Maximum hops")
	timeoutFlag := fs.Duration("timeout", 2*time.Second, "Timeout per probe")
	intervalFlag := fs.Duration("interval", 1*time.Second, "Time between cycles")
	noResolveFlag := fs.Bool("no-resolve", false, "Don't resolve hostnames")

	fs.IntVar(countFlag, "c", 10, "Number of cycles")
	fs.IntVar(maxHopsFlag, "m", 30, "Maximum hops")

	fs.Usage = func() {
		fmt.Println(`Usage: nns mtr [HOST] [OPTIONS]

My TraceRoute - combines ping and traceroute for real-time path analysis.
Shows packet loss and latency statistics for each hop (requires admin/root).

OPTIONS:
  -c, --count       Number of cycles to run (default: 10)
  -m, --max-hops    Maximum hops (default: 30)
  --timeout         Timeout per probe (default: 2s)
  --interval        Time between cycles (default: 1s)
  --no-resolve      Don't resolve hostnames
  --help            Show this help message

EXAMPLES:
  nns mtr google.com
  nns mtr -c 5 example.com
  nns mtr --no-resolve 8.8.8.8`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: target host required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	cfg := mtr.Config{
		Target:      target,
		MaxHops:     *maxHopsFlag,
		Timeout:     *timeoutFlag,
		Interval:    *intervalFlag,
		Count:       *countFlag,
		ResolveHost: !*noResolveFlag,
	}

	m := mtr.New(cfg)

	fmt.Printf("MTR to %s, %d cycles, %d hops max\n", target, cfg.Count, cfg.MaxHops)
	fmt.Println()

	err := m.Run(context.Background(), func(result *mtr.Result) {
		// Clear and redisplay (simple approach)
		fmt.Printf("\r%-3s %-16s %-25s %6s %8s %8s %8s %8s\n",
			"HOP", "IP", "HOST", "LOSS%", "SENT", "AVG", "BEST", "WORST")
		fmt.Println("--------------------------------------------------------------------------------------------")

		for _, hop := range result.GetActiveHops() {
			hostname := hop.Hostname
			if hostname == "" {
				hostname = "-"
			}
			if len(hostname) > 24 {
				hostname = hostname[:21] + "..."
			}

			fmt.Printf("%-3d %-16s %-25s %5.1f%% %8d %8v %8v %8v\n",
				hop.TTL, hop.IP, hostname,
				hop.LossPercent, hop.Sent,
				hop.AvgRTT.Round(time.Microsecond*100),
				hop.MinRTT.Round(time.Microsecond*100),
				hop.MaxRTT.Round(time.Microsecond*100))
		}
		fmt.Println()
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
