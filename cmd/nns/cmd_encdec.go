package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JedizLaPulga/NNS/internal/encdec"
)

func runEncDec(args []string) {
	fs := flag.NewFlagSet("encdec", flag.ExitOnError)
	format := fs.String("format", "", "Encoding format: base64, base64url, hex, url, binary")
	decode := fs.Bool("decode", false, "Decode instead of encode")
	detect := fs.Bool("detect", false, "Auto-detect encoding format")
	all := fs.Bool("all", false, "Encode in all formats")

	// Short flags
	fs.StringVar(format, "f", "", "Encoding format")
	fs.BoolVar(decode, "d", false, "Decode mode")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns encdec [options] <input>

Encode or decode data in common formats (Base64, Hex, URL, Binary).
Reads from arguments or stdin if no input provided.

Options:
  --format, -f   Encoding format: base64, base64url, hex, url, binary
  --decode, -d   Decode instead of encode
  --detect       Auto-detect encoding format of input
  --all          Encode input in all formats
  --help         Show this help message

Examples:
  nns encdec -f base64 "Hello, World!"         # Encode to base64
  nns encdec -f base64 -d "SGVsbG8="           # Decode from base64
  nns encdec -f hex "ABC"                       # Encode to hex
  nns encdec --detect "SGVsbG8sIFdvcmxkIQ=="   # Detect format
  nns encdec --all "secret"                     # Encode in all formats
  echo "data" | nns encdec -f base64            # Read from stdin
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Get input from args or stdin
	var input string
	if fs.NArg() > 0 {
		input = strings.Join(fs.Args(), " ")
	} else {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		input = strings.TrimRight(string(data), "\r\n")
	}

	if input == "" {
		fmt.Fprintf(os.Stderr, "Error: no input provided\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Mode: detect
	if *detect {
		fmt.Println("FORMAT DETECTION")
		fmt.Println()
		formats := encdec.DetectFormat(input)
		fmt.Print(encdec.FormatDetection(input, formats))
		return
	}

	// Mode: all formats
	if *all {
		fmt.Println("ENCODE ALL FORMATS")
		fmt.Println()
		results := encdec.EncodeAll(input)
		for i, r := range results {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("── %s ──\n", r.Format)
			fmt.Print(encdec.FormatResult(r))
		}
		return
	}

	// Mode: single encode/decode
	if *format == "" {
		fmt.Fprintf(os.Stderr, "Error: --format is required (use --detect or --all for alternatives)\n\n")
		fs.Usage()
		os.Exit(1)
	}

	f := encdec.Format(*format)

	if *decode {
		fmt.Printf("DECODE %s\n\n", strings.ToUpper(*format))
		r := encdec.Decode(input, f)
		fmt.Print(encdec.FormatResult(r))
		if !r.Valid {
			os.Exit(1)
		}
	} else {
		fmt.Printf("ENCODE %s\n\n", strings.ToUpper(*format))
		r := encdec.Encode(input, f)
		fmt.Print(encdec.FormatResult(r))
		if !r.Valid {
			os.Exit(1)
		}
	}
}
