package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/ipinfo"
)

func runIPInfo(args []string) {
	fs := flag.NewFlagSet("ipinfo", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Println(`Usage: nns ipinfo [IP] [OPTIONS]

Get IP geolocation and ASN information.

OPTIONS:
      --help    Show this help message

EXAMPLES:
  nns ipinfo              # Show your public IP info
  nns ipinfo 8.8.8.8      # Lookup specific IP
  nns ipinfo 1.1.1.1`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	ip := ""
	if fs.NArg() > 0 {
		ip = fs.Arg(0)
	}

	client := ipinfo.NewClient()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := client.Lookup(ctx, ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("IP Information for %s\n", info.IP)
	fmt.Println("════════════════════════════════════════════════════════════════")

	if info.IsPrivate {
		fmt.Println("  ⚠ This is a private IP address")
	} else if info.IsBogon {
		fmt.Println("  ⚠ This is a bogon/reserved IP address")
	}

	if info.Hostname != "" {
		fmt.Printf("  Hostname:     %s\n", info.Hostname)
	}
	if info.City != "" || info.Region != "" {
		fmt.Printf("  Location:     %s, %s\n", info.City, info.Region)
	}
	if info.Country != "" {
		flag := ipinfo.CountryFlag(info.CountryCode)
		fmt.Printf("  Country:      %s %s\n", flag, info.Country)
	}
	if info.Postal != "" {
		fmt.Printf("  Postal:       %s\n", info.Postal)
	}
	if info.Location != "" && info.Location != "0.0000, 0.0000" {
		fmt.Printf("  Coordinates:  %s\n", info.Location)
	}
	if info.Timezone != "" {
		fmt.Printf("  Timezone:     %s\n", info.Timezone)
	}
	if info.ASN != "" {
		fmt.Printf("  ASN:          %s\n", info.ASN)
	}
	if info.Org != "" {
		fmt.Printf("  Organization: %s\n", info.Org)
	}
	if info.ISP != "" && info.ISP != info.Org {
		fmt.Printf("  ISP:          %s\n", info.ISP)
	}

	fmt.Printf("\n  Query Time:   %v\n", info.Duration.Round(time.Millisecond))
}
