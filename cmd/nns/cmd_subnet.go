package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/JedizLaPulga/NNS/internal/subnet"
)

func runSubnet(args []string) {
	fs := flag.NewFlagSet("subnet", flag.ExitOnError)
	split := fs.Int("split", 0, "Split into smaller subnets with this prefix")
	listHosts := fs.Bool("hosts", false, "List usable host IPs")
	limit := fs.Int("limit", 100, "Max hosts to list")
	contains := fs.String("contains", "", "Check if subnet contains this IP")
	overlap := fs.String("overlap", "", "Check if subnet overlaps with another CIDR")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns subnet [options] <cidr>\n\n")
		fmt.Fprintf(os.Stderr, "Subnet calculator for network planning and analysis.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns subnet 192.168.1.0/24         # Calculate subnet info\n")
		fmt.Fprintf(os.Stderr, "  nns subnet --split 26 192.168.1.0/24  # Split into /26 subnets\n")
		fmt.Fprintf(os.Stderr, "  nns subnet --hosts 192.168.1.0/28     # List usable hosts\n")
		fmt.Fprintf(os.Stderr, "  nns subnet --contains 192.168.1.50 192.168.1.0/24\n")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	cidr := fs.Arg(0)

	// Handle contains check
	if *contains != "" {
		result, err := subnet.Contains(cidr, *contains)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if result {
			fmt.Printf("✓ %s contains %s\n", cidr, *contains)
		} else {
			fmt.Printf("✗ %s does NOT contain %s\n", cidr, *contains)
			os.Exit(1)
		}
		return
	}

	// Handle overlap check
	if *overlap != "" {
		result, err := subnet.Overlaps(cidr, *overlap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if result {
			fmt.Printf("⚠ %s OVERLAPS with %s\n", cidr, *overlap)
		} else {
			fmt.Printf("✓ %s does NOT overlap with %s\n", cidr, *overlap)
		}
		return
	}

	// Handle split
	if *split > 0 {
		subnets, err := subnet.Split(cidr, *split)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nSplitting %s into /%d subnets:\n\n", cidr, *split)
		for i, s := range subnets {
			info, _ := subnet.Calculate(s)
			fmt.Printf("  %2d. %-20s  Hosts: %-6d  Range: %s - %s\n",
				i+1, s, info.UsableHosts, info.FirstUsable, info.LastUsable)
		}
		fmt.Printf("\nTotal: %d subnets\n\n", len(subnets))
		return
	}

	// Handle list hosts
	if *listHosts {
		hosts, err := subnet.ListHosts(cidr, *limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		info, _ := subnet.Calculate(cidr)
		fmt.Printf("\nUsable hosts in %s (showing %d of %d):\n\n", cidr, len(hosts), info.UsableHosts)
		for i, h := range hosts {
			fmt.Printf("  %s", h)
			if (i+1)%5 == 0 {
				fmt.Println()
			} else {
				fmt.Print("\t")
			}
		}
		if len(hosts)%5 != 0 {
			fmt.Println()
		}
		fmt.Println()
		return
	}

	// Default: show subnet info
	info, err := subnet.Calculate(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	printSubnetInfo(info)
}

func printSubnetInfo(info *subnet.SubnetInfo) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  Subnet Calculator: %-40s ║\n", info.CIDR)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Network Address:    %-40s ║\n", info.NetworkAddress)
	fmt.Printf("║  Broadcast Address:  %-40s ║\n", info.BroadcastAddress)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Subnet Mask:        %-18s (/%d)%16s ║\n", info.SubnetMask, info.PrefixLength, "")
	fmt.Printf("║  Wildcard Mask:      %-40s ║\n", info.WildcardMask)
	fmt.Printf("║  Binary Mask:        %-40s ║\n", info.BinaryMask)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  First Usable Host:  %-40s ║\n", info.FirstUsable)
	fmt.Printf("║  Last Usable Host:   %-40s ║\n", info.LastUsable)
	fmt.Printf("║  Total Addresses:    %-40s ║\n", formatNumber(info.TotalHosts))
	fmt.Printf("║  Usable Hosts:       %-40s ║\n", formatNumber(info.UsableHosts))
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")

	privateLabel := "No (Public)"
	if info.IsPrivate {
		privateLabel = "Yes (Private)"
	}
	fmt.Printf("║  IP Class:           %-40s ║\n", info.IPClass)
	fmt.Printf("║  Private Network:    %-40s ║\n", privateLabel)
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func formatNumber(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if n >= 1000 {
		// Add thousand separators
		var result strings.Builder
		for i, c := range s {
			if i > 0 && (len(s)-i)%3 == 0 {
				result.WriteRune(',')
			}
			result.WriteRune(c)
		}
		return result.String()
	}
	return s
}
