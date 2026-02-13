package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JedizLaPulga/NNS/internal/jwtutil"
)

func runJWT(args []string) {
	fs := flag.NewFlagSet("jwt", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns jwt [options] <token>

Decode and analyze JWT (JSON Web Token) security.
Parses header and claims, checks for weak algorithms, expiration,
sensitive data in claims, and assigns a security grade (A-F).

The token can include or omit the "Bearer " prefix.
If no token argument is given, reads from stdin.

Options:
  --help    Show this help message

Examples:
  nns jwt eyJhbGci...
  nns jwt "Bearer eyJhbGci..."
  echo "eyJhbGci..." | nns jwt
  curl -s https://api.example.com/token | nns jwt
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var tokenStr string

	if fs.NArg() >= 1 {
		tokenStr = strings.Join(fs.Args(), "")
	} else {
		// Try reading from stdin
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
				os.Exit(1)
			}
			tokenStr = strings.TrimSpace(string(data))
		}
	}

	if tokenStr == "" {
		fmt.Fprintf(os.Stderr, "Error: JWT token required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	result, err := jwtutil.Decode(tokenStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(jwtutil.FormatResult(result))
}
