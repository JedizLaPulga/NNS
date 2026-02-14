package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/cidrmerge"
)

func runCIDRMerge(args []string) {
	fs := flag.NewFlagSet("cidrmerge", flag.ExitOnError)
	checkContains := fs.String("contains", "", "Check if a CIDR contains an IP (format: cidr,ip)")
	checkOverlap := fs.String("overlap", "", "Check if two CIDRs overlap (format: cidr1,cidr2)")
	exclude := fs.String("exclude", "", "Exclude a range from a CIDR (format: base,exclude)")
	hostCount := fs.String("hosts", "", "Count usable hosts in a CIDR")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns cidrmerge [options] <cidr> [cidr...]

Merge, deduplicate, and consolidate overlapping or adjacent CIDR ranges.
Produces a minimal set of prefixes covering the same IP space.

Options:
  --contains     Check if CIDR contains IP (format: cidr,ip)
  --overlap      Check if two CIDRs overlap (format: cidr1,cidr2)
  --exclude      Exclude range from CIDR (format: base,exclude)
  --hosts        Count usable hosts in a CIDR
  --help         Show this help message

Examples:
  nns cidrmerge 10.0.0.0/24 10.0.1.0/24         # Merge adjacent
  nns cidrmerge 10.0.0.0/16 10.0.1.0/24          # Remove contained
  nns cidrmerge --contains 10.0.0.0/24,10.0.0.50 # Check containment
  nns cidrmerge --overlap 10.0.0.0/24,10.0.0.128/25
  nns cidrmerge --exclude 10.0.0.0/24,10.0.0.0/25
  nns cidrmerge --hosts 10.0.0.0/24              # Count hosts
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Mode: contains
	if *checkContains != "" {
		parts := splitTwo(*checkContains)
		if parts == nil {
			fmt.Fprintf(os.Stderr, "Error: --contains requires format: cidr,ip\n")
			os.Exit(1)
		}
		ok, err := cidrmerge.Contains(parts[0], parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if ok {
			fmt.Printf("✓ %s contains %s\n", parts[0], parts[1])
		} else {
			fmt.Printf("✗ %s does NOT contain %s\n", parts[0], parts[1])
		}
		return
	}

	// Mode: overlap
	if *checkOverlap != "" {
		parts := splitTwo(*checkOverlap)
		if parts == nil {
			fmt.Fprintf(os.Stderr, "Error: --overlap requires format: cidr1,cidr2\n")
			os.Exit(1)
		}
		ok, err := cidrmerge.Overlaps(parts[0], parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if ok {
			fmt.Printf("✓ %s and %s overlap\n", parts[0], parts[1])
		} else {
			fmt.Printf("✗ %s and %s do NOT overlap\n", parts[0], parts[1])
		}
		return
	}

	// Mode: exclude
	if *exclude != "" {
		parts := splitTwo(*exclude)
		if parts == nil {
			fmt.Fprintf(os.Stderr, "Error: --exclude requires format: base,exclude\n")
			os.Exit(1)
		}
		remaining, err := cidrmerge.Exclude(parts[0], parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CIDR EXCLUDE %s - %s\n\n", parts[0], parts[1])
		fmt.Printf("  Remaining prefixes: %d\n", len(remaining))
		for _, r := range remaining {
			count, _ := cidrmerge.HostCount(r)
			if count != nil {
				fmt.Printf("    %-20s (%s hosts)\n", r, count.String())
			} else {
				fmt.Printf("    %s\n", r)
			}
		}
		return
	}

	// Mode: host count
	if *hostCount != "" {
		count, err := cidrmerge.HostCount(*hostCount)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("CIDR HOST COUNT %s\n\n", *hostCount)
		fmt.Printf("  Usable hosts: %s\n", count.String())
		return
	}

	// Mode: merge
	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: at least one CIDR required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	cidrs := fs.Args()
	fmt.Printf("CIDR MERGE (%d prefixes)\n\n", len(cidrs))

	result := cidrmerge.Merge(cidrs)
	fmt.Print(cidrmerge.FormatResult(result))
}

func splitTwo(s string) []string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ',' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}
