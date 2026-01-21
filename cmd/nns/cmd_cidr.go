package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/cidr"
)

func runCIDR(args []string) {
	fs := flag.NewFlagSet("cidr", flag.ExitOnError)

	containsFlag := fs.String("contains", "", "Check if IP is in CIDR range")
	splitFlag := fs.Int("split", 0, "Split into smaller subnets with this prefix")
	rangeFlag := fs.Bool("range", false, "List all IPs in range")

	fs.Usage = func() {
		fmt.Println(`Usage: nns cidr [CIDR] [OPTIONS]

CIDR/subnet calculator and utilities.

OPTIONS:
      --contains    Check if IP is within CIDR range
      --split       Split into smaller subnets (specify new prefix)
      --range       List all IPs in the range
      --help        Show this help message

EXAMPLES:
  nns cidr 192.168.1.0/24
  nns cidr 10.0.0.0/8 --contains 10.1.2.3
  nns cidr 192.168.0.0/24 --split 26
  nns cidr 192.168.1.0/28 --range`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: CIDR required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	cidrStr := fs.Arg(0)

	// Check if IP is in range
	if *containsFlag != "" {
		contains, err := cidr.Contains(cidrStr, *containsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if contains {
			fmt.Printf("✓ %s is within %s\n", *containsFlag, cidrStr)
		} else {
			fmt.Printf("✗ %s is NOT within %s\n", *containsFlag, cidrStr)
		}
		return
	}

	// Split subnet
	if *splitFlag > 0 {
		subnets, err := cidr.Split(cidrStr, *splitFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Splitting %s into /%d subnets:\n\n", cidrStr, *splitFlag)
		for i, subnet := range subnets {
			fmt.Printf("  %d. %s\n", i+1, subnet)
		}
		fmt.Printf("\nTotal: %d subnets\n", len(subnets))
		return
	}

	// List all IPs
	if *rangeFlag {
		ips, err := cidr.IPRange(cidrStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, ip := range ips {
			fmt.Println(ip)
		}
		return
	}

	// Default: show subnet info
	subnet, err := cidr.Parse(cidrStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Subnet Information for %s\n", subnet.CIDR)
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Printf("  Network:       %s\n", subnet.NetworkAddress)
	if !subnet.IsIPv6 {
		fmt.Printf("  Broadcast:     %s\n", subnet.BroadcastAddr)
		fmt.Printf("  Subnet Mask:   %s\n", subnet.SubnetMask)
		fmt.Printf("  Wildcard:      %s\n", subnet.WildcardMask)
	}
	fmt.Printf("  First Host:    %s\n", subnet.FirstHost)
	fmt.Printf("  Last Host:     %s\n", subnet.LastHost)
	fmt.Printf("  Prefix:        /%d\n", subnet.Prefix)
	if subnet.TotalHosts > 0 {
		fmt.Printf("  Total Hosts:   %d\n", subnet.TotalHosts)
		fmt.Printf("  Usable Hosts:  %d\n", subnet.UsableHosts)
	}
}
