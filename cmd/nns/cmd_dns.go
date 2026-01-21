package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/dns"
)

func runDNS(args []string) {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)

	typeFlag := fs.String("type", "A", "Record type (A, AAAA, MX, TXT, NS, CNAME, PTR, SOA)")
	resolverFlag := fs.String("resolver", "", "Custom DNS server (e.g., 8.8.8.8)")
	allFlag := fs.Bool("all", false, "Query all common record types")
	shortFlag := fs.Bool("short", false, "Show only record values")
	propagationFlag := fs.Bool("propagation", false, "Check DNS propagation across global resolvers")

	// Short flags
	fs.StringVar(typeFlag, "t", "A", "Record type")
	fs.StringVar(resolverFlag, "r", "", "Custom DNS server")
	fs.BoolVar(propagationFlag, "p", false, "Check propagation")

	fs.Usage = func() {
		fmt.Println(`Usage: nns dns [HOST] [OPTIONS]

Perform DNS lookups for various record types.

OPTIONS:
  -t, --type        Record type: A, AAAA, MX, TXT, NS, CNAME, PTR, SOA (default: A)
  -r, --resolver    Custom DNS server (e.g., 8.8.8.8, 1.1.1.1)
      --all         Query all common record types (A, AAAA, MX, TXT, NS, CNAME, SOA)
  -p, --propagation Check DNS propagation across global resolvers
      --short       Show only record values (for scripting)
      --help        Show this help message

EXAMPLES:
  nns dns google.com                  # A record lookup
  nns dns google.com --type MX        # Mail servers
  nns dns google.com --type TXT       # TXT records (SPF, DKIM)
  nns dns google.com --type SOA       # Authoritative server info
  nns dns 8.8.8.8 --type PTR          # Reverse lookup
  nns dns google.com --all            # All record types
  nns dns google.com --propagation    # Check global DNS propagation
  nns dns google.com --resolver 1.1.1.1`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: hostname or IP required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	// Create resolver
	resolver := dns.NewResolver()
	if *resolverFlag != "" {
		resolver.SetServer(*resolverFlag)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Auto-detect PTR for IP addresses
	recordType := *typeFlag
	if dns.IsIPAddress(target) && recordType == "A" {
		recordType = "PTR"
	}

	if *propagationFlag {
		// Propagation check
		rt, err := dns.ParseRecordType(recordType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Checking DNS propagation for %s (%s)...\n\n", target, rt)

		pr := dns.CheckPropagation(ctx, target, rt)

		fmt.Printf("%-12s %-16s %-10s %s\n", "RESOLVER", "IP", "TIME", "RECORDS")
		fmt.Println("----------------------------------------------------------------")

		for _, r := range pr.Results {
			var recordStr string
			if r.Error != nil {
				recordStr = fmt.Sprintf("ERROR: %v", r.Error)
			} else if len(r.Records) == 0 {
				recordStr = "(no records)"
			} else {
				for i, rec := range r.Records {
					if i > 0 {
						recordStr += ", "
					}
					recordStr += rec.Value
				}
				if len(recordStr) > 35 {
					recordStr = recordStr[:32] + "..."
				}
			}
			fmt.Printf("%-12s %-16s %-10s %s\n", r.Name, r.Resolver, r.Duration.Round(time.Millisecond), recordStr)
		}

		fmt.Println()
		if pr.IsPropagated() {
			fmt.Println("✓ DNS is fully propagated across all resolvers")
		} else {
			fmt.Println("✗ DNS is NOT fully propagated (results differ)")
		}
	} else if *allFlag {
		// Query all types
		fmt.Printf("DNS lookup for %s (all types)\n", target)
		if *resolverFlag != "" {
			fmt.Printf("Using resolver: %s\n", *resolverFlag)
		}
		fmt.Println()

		results := resolver.LookupAll(ctx, target)
		for _, result := range results {
			printDNSResult(&result, *shortFlag)
		}
	} else {
		// Single type query
		rt, err := dns.ParseRecordType(recordType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if !*shortFlag {
			fmt.Printf("DNS lookup for %s (type: %s)\n", target, rt)
			if *resolverFlag != "" {
				fmt.Printf("Using resolver: %s\n", *resolverFlag)
			}
			fmt.Println()
		}

		result := resolver.Lookup(ctx, target, rt)
		printDNSResult(result, *shortFlag)
	}
}

func printDNSResult(result *dns.Result, short bool) {
	if result.Error != nil {
		if !short {
			fmt.Printf("%-6s  (no records: %v)\n", result.Type, result.Error)
		}
		return
	}

	// Handle SOA separately
	if result.Type == dns.TypeSOA && result.SOA != nil {
		if short {
			fmt.Println(result.SOA.PrimaryNS)
			return
		}
		fmt.Printf("%-6s  Primary NS: %s\n", result.Type, result.SOA.PrimaryNS)
		fmt.Printf("        Admin: %s\n", result.SOA.AdminEmail)
		fmt.Printf("        Query time: %v\n\n", result.Duration)
		return
	}

	if len(result.Records) == 0 {
		if !short {
			fmt.Printf("%-6s  (no records)\n", result.Type)
		}
		return
	}

	if short {
		for _, rec := range result.Records {
			fmt.Println(rec.Value)
		}
		return
	}

	// Verbose output
	for _, rec := range result.Records {
		if rec.Priority > 0 {
			fmt.Printf("%-6s  %d %s\n", rec.Type, rec.Priority, rec.Value)
		} else {
			fmt.Printf("%-6s  %s\n", rec.Type, rec.Value)
		}
	}

	fmt.Printf("        Query time: %v\n\n", result.Duration)
}
