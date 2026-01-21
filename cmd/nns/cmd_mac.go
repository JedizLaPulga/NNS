package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/macutil"
)

func runMAC(args []string) {
	fs := flag.NewFlagSet("mac", flag.ExitOnError)

	generateFlag := fs.Bool("generate", false, "Generate random MAC address")
	formatFlag := fs.String("format", "colon", "Output format: colon, dash, dot, bare, upper")
	ouiFlag := fs.String("oui", "", "Generate MAC with specific OUI")

	// Short flags
	fs.BoolVar(generateFlag, "g", false, "Generate")
	fs.StringVar(formatFlag, "f", "colon", "Format")

	fs.Usage = func() {
		fmt.Println(`Usage: nns mac [MAC] [OPTIONS]

MAC address utilities - lookup, format, generate.

OPTIONS:
  -g, --generate   Generate random MAC address
  -f, --format     Output format: colon, dash, dot, bare, upper
      --oui        Generate with specific OUI (e.g., 00:50:56)
      --help       Show this help message

EXAMPLES:
  nns mac aa:bb:cc:dd:ee:ff       # Lookup vendor
  nns mac --generate              # Random MAC
  nns mac --generate --oui 00:50:56  # VMware MAC
  nns mac aa-bb-cc-dd-ee-ff --format dot`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// Generate MAC
	if *generateFlag {
		var mac string
		if *ouiFlag != "" {
			var err error
			mac, err = macutil.GenerateWithOUI(*ouiFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			mac = macutil.Generate(true)
		}

		formatted := macutil.Format(mac, *formatFlag)
		info, _ := macutil.Parse(mac)

		fmt.Printf("Generated MAC: %s\n", formatted)
		if info != nil && info.Vendor != "" {
			fmt.Printf("Vendor:        %s\n", info.Vendor)
		}
		if info != nil {
			fmt.Printf("OUI:           %s\n", info.OUI)
			if info.IsLocal {
				fmt.Println("Type:          Locally Administered")
			} else {
				fmt.Println("Type:          Universally Administered")
			}
		}
		return
	}

	// Lookup MAC
	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: MAC address required (or use --generate)\n\n")
		fs.Usage()
		os.Exit(1)
	}

	mac := fs.Arg(0)
	info, err := macutil.Parse(mac)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	formatted := macutil.Format(mac, *formatFlag)

	fmt.Printf("MAC Address Information\n")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Printf("  MAC:           %s\n", formatted)
	fmt.Printf("  Normalized:    %s\n", info.Normalized)
	fmt.Printf("  OUI:           %s\n", info.OUI)
	if info.Vendor != "" {
		fmt.Printf("  Vendor:        %s\n", info.Vendor)
	} else {
		fmt.Printf("  Vendor:        Unknown\n")
	}

	macType := "Unicast"
	if info.IsMulticast {
		macType = "Multicast"
	}
	fmt.Printf("  Cast Type:     %s\n", macType)

	adminType := "Universally Administered (UAA)"
	if info.IsLocal {
		adminType = "Locally Administered (LAA)"
	}
	fmt.Printf("  Admin Type:    %s\n", adminType)

	if macutil.IsBroadcast(mac) {
		fmt.Println("  Special:       Broadcast Address")
	} else if macutil.IsZero(mac) {
		fmt.Println("  Special:       Zero/Null Address")
	}
}
