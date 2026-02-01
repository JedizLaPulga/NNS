package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"nns/internal/geoloc"
)

func runGeoloc(args []string) {
	fs := flag.NewFlagSet("geoloc", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "Lookup timeout")
	batch := fs.Bool("batch", false, "Batch mode for multiple IPs")
	json := fs.Bool("json", false, "Output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns geoloc [options] <ip...>\n\n")
		fmt.Fprintf(os.Stderr, "Geolocate IP addresses with city, country, ASN, and coordinates.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns geoloc 8.8.8.8\n")
		fmt.Fprintf(os.Stderr, "  nns geoloc 1.1.1.1 8.8.4.4 9.9.9.9\n")
		fmt.Fprintf(os.Stderr, "  nns geoloc --json 8.8.8.8\n")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	cfg := geoloc.DefaultConfig()
	cfg.Timeout = *timeout
	client := geoloc.NewClient(cfg)
	ctx := context.Background()

	ips := fs.Args()

	if *batch || len(ips) > 1 {
		results := client.LookupBatch(ctx, ips)
		if *json {
			printGeolocJSON(results)
		} else {
			printGeolocTable(results, ips)
		}
	} else {
		info, err := client.Lookup(ctx, ips[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if *json {
			printGeolocSingleJSON(info)
		} else {
			printGeolocSingle(info)
		}
	}
}

func printGeolocSingle(info *geoloc.GeoInfo) {
	fmt.Printf("\n%s IP Geolocation: %s\n\n", info.CountryFlag(), info.IP)

	if info.IsPrivate {
		fmt.Println("  Type:        Private/Local Network")
		fmt.Printf("  Lookup Time: %v\n\n", info.LookupTime)
		return
	}

	if info.Error != nil {
		fmt.Printf("  Error: %v\n\n", info.Error)
		return
	}

	fmt.Printf("  Location:    %s\n", info.FormatLocation())
	fmt.Printf("  Country:     %s (%s)\n", info.Country, info.CountryCode)
	if info.Region != "" {
		fmt.Printf("  Region:      %s\n", info.Region)
	}
	if info.City != "" {
		fmt.Printf("  City:        %s\n", info.City)
	}
	fmt.Printf("  Coordinates: %.4f, %.4f\n", info.Latitude, info.Longitude)
	if info.ASN > 0 {
		fmt.Printf("  ASN:         AS%d (%s)\n", info.ASN, info.ASNOrg)
	}
	if info.ISP != "" {
		fmt.Printf("  ISP:         %s\n", info.ISP)
	}
	if info.Timezone != "" {
		fmt.Printf("  Timezone:    %s\n", info.Timezone)
	}
	fmt.Printf("  Lookup Time: %v\n\n", info.LookupTime)
}

func printGeolocTable(results map[string]*geoloc.GeoInfo, order []string) {
	fmt.Printf("\n%-16s %-4s %-24s %-20s %-8s\n", "IP", "Flag", "Location", "ISP/ASN", "Time")
	fmt.Println(strings.Repeat("-", 80))

	for _, ip := range order {
		info := results[ip]
		if info == nil {
			continue
		}

		flag := info.CountryFlag()
		loc := info.FormatLocation()
		if len(loc) > 24 {
			loc = loc[:21] + "..."
		}

		isp := info.ISP
		if info.ASN > 0 && isp == "" {
			isp = fmt.Sprintf("AS%d", info.ASN)
		}
		if len(isp) > 20 {
			isp = isp[:17] + "..."
		}

		fmt.Printf("%-16s %-4s %-24s %-20s %v\n", ip, flag, loc, isp, info.LookupTime.Round(time.Millisecond))
	}
	fmt.Println()
}

func printGeolocJSON(results map[string]*geoloc.GeoInfo) {
	fmt.Println("[")
	i := 0
	for _, info := range results {
		if i > 0 {
			fmt.Println(",")
		}
		printGeolocSingleJSON(info)
		i++
	}
	fmt.Println("\n]")
}

func printGeolocSingleJSON(info *geoloc.GeoInfo) {
	fmt.Printf(`  {"ip":"%s","country":"%s","country_code":"%s","region":"%s","city":"%s","lat":%.4f,"lon":%.4f,"asn":%d,"isp":"%s","private":%v}`,
		info.IP, info.Country, info.CountryCode, info.Region, info.City,
		info.Latitude, info.Longitude, info.ASN, info.ISP, info.IsPrivate)
}
