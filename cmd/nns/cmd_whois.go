package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/whois"
)

func runWhois(args []string) {
	fs := flag.NewFlagSet("whois", flag.ExitOnError)

	rawFlag := fs.Bool("raw", false, "Show raw WHOIS response")
	serverFlag := fs.String("server", "", "Custom WHOIS server")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Query timeout")

	// Short flags
	fs.StringVar(serverFlag, "s", "", "WHOIS server")
	fs.DurationVar(timeoutFlag, "t", 10*time.Second, "Timeout")

	fs.Usage = func() {
		fmt.Println(`Usage: nns whois [TARGET] [OPTIONS]

WHOIS lookup for domains and IP addresses.

OPTIONS:
  -s, --server    Custom WHOIS server
  -t, --timeout   Query timeout (default: 10s)
      --raw       Show raw WHOIS response
      --help      Show this help message

EXAMPLES:
  nns whois google.com
  nns whois 8.8.8.8
  nns whois amazon.com --raw`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: domain or IP required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	target := fs.Arg(0)

	client := whois.NewClient()
	client.Timeout = *timeoutFlag
	if *serverFlag != "" {
		client.Server = *serverFlag
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	result, err := client.Lookup(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *rawFlag {
		fmt.Println(result.Raw)
		return
	}

	// Pretty print
	fmt.Printf("WHOIS for %s (%s)\n", target, result.Type)
	fmt.Println("════════════════════════════════════════════════════════════════")

	if result.Type == "domain" {
		if result.Registrar != "" {
			fmt.Printf("  Registrar:      %s\n", result.Registrar)
		}
		if result.Organization != "" {
			fmt.Printf("  Organization:   %s\n", result.Organization)
		}
		if result.CreatedDate != "" {
			fmt.Printf("  Created:        %s\n", result.CreatedDate)
		}
		if result.UpdatedDate != "" {
			fmt.Printf("  Updated:        %s\n", result.UpdatedDate)
		}
		if result.ExpiresDate != "" {
			fmt.Printf("  Expires:        %s\n", result.ExpiresDate)
			days := result.DaysUntilExpiry()
			if days >= 0 {
				if days < 30 {
					fmt.Printf("                  ⚠ Expires in %d days!\n", days)
				} else {
					fmt.Printf("                  (%d days remaining)\n", days)
				}
			}
		}
		if result.Country != "" {
			fmt.Printf("  Country:        %s\n", result.Country)
		}
		if len(result.NameServers) > 0 {
			fmt.Printf("  Name Servers:\n")
			for _, ns := range result.NameServers {
				fmt.Printf("                  %s\n", ns)
			}
		}
	} else {
		// IP WHOIS
		if result.Organization != "" {
			fmt.Printf("  Organization:   %s\n", result.Organization)
		}
		if result.NetName != "" {
			fmt.Printf("  Network Name:   %s\n", result.NetName)
		}
		if result.NetRange != "" {
			fmt.Printf("  Net Range:      %s\n", result.NetRange)
		}
		if result.CIDR != "" {
			fmt.Printf("  CIDR:           %s\n", result.CIDR)
		}
		if result.Country != "" {
			fmt.Printf("  Country:        %s\n", result.Country)
		}
	}

	fmt.Printf("\n  Server:         %s\n", result.Server)
	fmt.Printf("  Query Time:     %v\n", result.Duration.Round(time.Millisecond))
}
