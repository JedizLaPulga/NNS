package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/arp"
)

func runARP(args []string) {
	fs := flag.NewFlagSet("arp", flag.ExitOnError)

	interfaceFlag := fs.String("interface", "", "Filter by interface")
	vendorFlag := fs.Bool("vendor", true, "Show MAC vendor")

	// Short flags
	fs.StringVar(interfaceFlag, "i", "", "Interface filter")
	fs.BoolVar(vendorFlag, "v", true, "Show vendor")

	fs.Usage = func() {
		fmt.Println(`Usage: nns arp [OPTIONS]

View the system ARP table with MAC vendor lookup.

OPTIONS:
  -i, --interface    Filter by network interface
  -v, --vendor       Show MAC vendor (default: true)
      --help         Show this help message

EXAMPLES:
  nns arp
  nns arp --interface eth0`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	entries, err := arp.GetTable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Filter by interface
	if *interfaceFlag != "" {
		entries = arp.FilterByInterface(entries, *interfaceFlag)
	}

	if len(entries) == 0 {
		fmt.Println("No ARP entries found")
		return
	}

	// Print header
	if *vendorFlag {
		fmt.Printf("%-16s %-20s %-12s %-15s %s\n", "IP", "MAC", "INTERFACE", "TYPE", "VENDOR")
	} else {
		fmt.Printf("%-16s %-20s %-12s %s\n", "IP", "MAC", "INTERFACE", "TYPE")
	}
	fmt.Println("────────────────────────────────────────────────────────────────────────────")

	for _, e := range entries {
		if *vendorFlag {
			vendor := e.Vendor
			if vendor == "" {
				vendor = "-"
			}
			fmt.Printf("%-16s %-20s %-12s %-15s %s\n", e.IP, e.MAC, e.Interface, e.Type, vendor)
		} else {
			fmt.Printf("%-16s %-20s %-12s %s\n", e.IP, e.MAC, e.Interface, e.Type)
		}
	}

	fmt.Printf("\nTotal: %d entries\n", len(entries))
}
