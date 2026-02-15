package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/netcalc"
)

func runNetcalc(args []string) {
	fs := flag.NewFlagSet("netcalc", flag.ExitOnError)
	add := fs.Int64("add", 0, "Add offset to IP address")
	rangeEnd := fs.String("range", "", "End IP for range listing")
	maxRange := fs.Int("max", 256, "Maximum IPs to list in range mode")
	binary := fs.Bool("binary", false, "Show binary representation of IP")

	// Short flags
	fs.BoolVar(binary, "b", false, "Binary mode")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns netcalc [options] <cidr|ip>

Network calculator for IP math, subnet info, and binary representation.

Options:
  --add          Add offset to IP (positive or negative)
  --range        End IP to enumerate range (start is positional arg)
  --max          Max IPs to list in range mode (default: 256)
  --binary, -b   Show binary representation only
  --help         Show this help message

Examples:
  nns netcalc 192.168.1.0/24             # Full subnet info
  nns netcalc 10.0.0.1                   # Info for single IP (/32)
  nns netcalc 10.0.0.1 --add 10          # IP arithmetic: 10.0.0.11
  nns netcalc 10.0.0.1 --range 10.0.0.10 # List IP range
  nns netcalc 192.168.1.1 -b             # Binary representation
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: IP or CIDR required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	// Mode: binary
	if *binary {
		bin, err := netcalc.IPToBinary(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("IP BINARY\n\n")
		fmt.Printf("  IP:      %s\n", target)
		fmt.Printf("  Binary:  %s\n", bin)
		return
	}

	// Mode: add offset
	if *add != 0 {
		result, err := netcalc.AddToIP(target, *add)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("IP ARITHMETIC\n\n")
		fmt.Printf("  Base IP:  %s\n", target)
		fmt.Printf("  Offset:   %+d\n", *add)
		fmt.Printf("  Result:   %s\n", result)
		return
	}

	// Mode: range
	if *rangeEnd != "" {
		ips, err := netcalc.IPRange(target, *rangeEnd, *maxRange)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("IP RANGE %s → %s\n\n", target, *rangeEnd)
		fmt.Printf("  Count: %d\n\n", len(ips))
		for _, ip := range ips {
			fmt.Printf("  %s\n", ip)
		}
		return
	}

	// Mode: calculate (default)
	fmt.Printf("NETWORK CALCULATOR\n\n")
	info, err := netcalc.Calculate(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(netcalc.FormatInfo(info))
}
