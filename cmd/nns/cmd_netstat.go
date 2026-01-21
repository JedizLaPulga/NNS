package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/netstat"
)

func runNetstat(args []string) {
	fs := flag.NewFlagSet("netstat", flag.ExitOnError)

	tcpFlag := fs.Bool("tcp", false, "Show TCP only")
	udpFlag := fs.Bool("udp", false, "Show UDP only")
	listenFlag := fs.Bool("listen", false, "Show listening only")
	allFlag := fs.Bool("all", false, "Show all connections")
	pidFlag := fs.Bool("pid", false, "Show process IDs (requires admin)")
	routingFlag := fs.Bool("routing", false, "Show routing table")

	// Short flags
	fs.BoolVar(tcpFlag, "t", false, "TCP only")
	fs.BoolVar(udpFlag, "u", false, "UDP only")
	fs.BoolVar(listenFlag, "l", false, "Listening only")
	fs.BoolVar(allFlag, "a", false, "All connections")
	fs.BoolVar(pidFlag, "p", false, "Show PIDs")
	fs.BoolVar(routingFlag, "r", false, "Routing table")

	fs.Usage = func() {
		fmt.Println(`Usage: nns netstat [OPTIONS]

Show network connections and routing information.

OPTIONS:
  -t, --tcp       Show TCP connections only
  -u, --udp       Show UDP connections only
  -l, --listen    Show listening ports only
  -a, --all       Show all connections
  -p, --pid       Show process IDs (requires admin)
  -r, --routing   Show routing table instead of connections
      --help      Show this help message

EXAMPLES:
  nns netstat
  nns netstat --listen
  nns netstat --tcp --pid
  nns netstat --routing`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Show routing table
	if *routingFlag {
		routes, err := netstat.GetRoutingTable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("%-18s %-18s %-18s %-12s %s\n", "DESTINATION", "GATEWAY", "MASK", "INTERFACE", "METRIC")
		fmt.Println("────────────────────────────────────────────────────────────────────────────────")

		for _, r := range routes {
			mask := r.Mask
			if mask == "" {
				mask = "-"
			}
			fmt.Printf("%-18s %-18s %-18s %-12s %d\n", r.Destination, r.Gateway, mask, r.Interface, r.Metric)
		}

		fmt.Printf("\nTotal: %d routes\n", len(routes))
		return
	}

	// Show connections
	conns, err := netstat.GetConnections(*pidFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Apply filters
	if *tcpFlag {
		conns = netstat.FilterByProtocol(conns, "tcp")
	} else if *udpFlag {
		conns = netstat.FilterByProtocol(conns, "udp")
	}

	if *listenFlag {
		conns = netstat.GetListening(conns)
	}

	if len(conns) == 0 {
		fmt.Println("No connections found")
		return
	}

	// Print header
	if *pidFlag {
		fmt.Printf("%-8s %-25s %-25s %-15s %s\n", "PROTO", "LOCAL", "REMOTE", "STATE", "PID")
	} else {
		fmt.Printf("%-8s %-25s %-25s %s\n", "PROTO", "LOCAL", "REMOTE", "STATE")
	}
	fmt.Println("────────────────────────────────────────────────────────────────────────────────")

	for _, c := range conns {
		local := fmt.Sprintf("%s:%d", c.LocalAddr, c.LocalPort)
		remote := fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort)
		if c.RemoteAddr == "" || c.RemotePort == 0 {
			remote = "*:*"
		}

		state := c.State
		if state == "" {
			state = "-"
		}

		if *pidFlag {
			fmt.Printf("%-8s %-25s %-25s %-15s %d\n", c.Protocol, local, remote, state, c.PID)
		} else {
			fmt.Printf("%-8s %-25s %-25s %s\n", c.Protocol, local, remote, state)
		}
	}

	fmt.Printf("\nTotal: %d connections\n", len(conns))
}
