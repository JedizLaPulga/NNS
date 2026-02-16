package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/ipconv"
)

func runIPConv(args []string) {
	fs := flag.NewFlagSet("ipconv", flag.ExitOnError)
	fromInt := fs.Bool("from-int", false, "Interpret input as decimal integer")
	all := fs.Bool("all", false, "Convert multiple IPs (remaining args)")

	// Short flags
	fs.BoolVar(fromInt, "i", false, "From integer")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns ipconv [options] <ip-or-integer>

Convert IP addresses between formats: decimal, hex, octal, binary, integer.
Accepts standard dotted decimal, hex (0xC0A80101 or 0xC0.0xA8.0x01.0x01),
octal (0300.0250.0001.0001), or plain integers.

Options:
  --from-int, -i   Interpret input as a decimal integer
  --all            Convert all remaining arguments
  --help           Show this help message

Examples:
  nns ipconv 192.168.1.1                   # Show all representations
  nns ipconv 0xC0A80101                    # From hex integer
  nns ipconv 0xC0.0xA8.0x01.0x01          # From hex dotted
  nns ipconv -i 3232235777                 # From decimal integer
  nns ipconv ::1                           # IPv6
  nns ipconv --all 10.0.0.1 172.16.0.1    # Multiple IPs
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: IP address or integer required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	inputs := fs.Args()
	if !*all {
		inputs = inputs[:1]
	}

	fmt.Printf("IP ADDRESS CONVERTER\n\n")

	for idx, input := range inputs {
		if idx > 0 {
			fmt.Println()
		}

		var c ipconv.Conversion
		if *fromInt {
			c = ipconv.FromInteger(input)
		} else {
			c = ipconv.Convert(input)
		}

		fmt.Printf("── %s ──\n", input)
		fmt.Print(ipconv.FormatConversion(c))

		if !c.Valid {
			os.Exit(1)
		}
	}
}
