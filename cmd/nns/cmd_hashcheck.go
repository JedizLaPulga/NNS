package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/JedizLaPulga/NNS/internal/hashcheck"
)

func runHashCheck(args []string) {
	fs := flag.NewFlagSet("hashcheck", flag.ExitOnError)
	algo := fs.String("algo", "sha256", "Hash algorithm: md5, sha1, sha256, sha512")
	file := fs.String("file", "", "File to hash (instead of string)")
	compare := fs.String("compare", "", "Expected hash to compare against")
	all := fs.Bool("all", false, "Compute all hash algorithms")

	// Short flags
	fs.StringVar(algo, "a", "sha256", "Hash algorithm")
	fs.StringVar(file, "f", "", "File to hash")
	fs.StringVar(compare, "c", "", "Compare hash")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns hashcheck [options] <input>

Compute cryptographic hashes for strings or files.
Supports MD5, SHA-1, SHA-256, and SHA-512.

Options:
  --algo, -a     Hash algorithm: md5, sha1, sha256, sha512 (default: sha256)
  --file, -f     Hash a file instead of a string
  --compare, -c  Expected hash to verify against
  --all          Compute all algorithms
  --help         Show this help message

Examples:
  nns hashcheck "Hello, World!"                  # SHA-256 of string
  nns hashcheck -a md5 "test"                    # MD5 of string
  nns hashcheck -f /path/to/file                 # SHA-256 of file
  nns hashcheck -f app.exe -c abc123...          # Verify file hash
  nns hashcheck --all "secret"                   # All algorithms
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	algorithm := hashcheck.Algorithm(strings.ToLower(*algo))

	// Mode: hash file
	if *file != "" {
		if *all {
			fmt.Printf("HASH FILE (all algorithms)\n  %s\n\n", *file)
			results := hashcheck.HashFileAll(*file)
			for _, r := range results {
				fmt.Printf("── %s ──\n", strings.ToUpper(string(r.Algorithm)))
				fmt.Print(hashcheck.FormatResult(r))
				fmt.Println()
			}
		} else {
			fmt.Printf("HASH FILE %s\n\n", strings.ToUpper(*algo))
			r := hashcheck.HashFile(*file, algorithm)
			fmt.Print(hashcheck.FormatResult(r))
			if !r.Valid {
				os.Exit(1)
			}
			if *compare != "" {
				fmt.Println()
				cr := hashcheck.Compare(r, *compare)
				fmt.Print(hashcheck.FormatCompare(cr))
				if !cr.Match {
					os.Exit(1)
				}
			}
		}
		return
	}

	// Mode: hash string
	var input string
	if fs.NArg() > 0 {
		input = strings.Join(fs.Args(), " ")
	} else {
		fmt.Fprintf(os.Stderr, "Error: input string or --file required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *all {
		fmt.Printf("HASH ALL ALGORITHMS\n\n")
		results := hashcheck.HashAll(input)
		for _, r := range results {
			fmt.Printf("── %s ──\n", strings.ToUpper(string(r.Algorithm)))
			fmt.Print(hashcheck.FormatResult(r))
			fmt.Println()
		}
	} else {
		fmt.Printf("HASH %s\n\n", strings.ToUpper(*algo))
		r := hashcheck.HashString(input, algorithm)
		fmt.Print(hashcheck.FormatResult(r))
		if !r.Valid {
			os.Exit(1)
		}
		if *compare != "" {
			fmt.Println()
			cr := hashcheck.Compare(r, *compare)
			fmt.Print(hashcheck.FormatCompare(cr))
			if !cr.Match {
				os.Exit(1)
			}
		}
	}
}
