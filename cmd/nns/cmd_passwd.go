package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JedizLaPulga/NNS/internal/passwd"
)

func runPasswd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	generate := fs.Bool("generate", false, "Generate a secure password")
	length := fs.Int("length", 16, "Password length for generation")
	count := fs.Int("count", 1, "Number of passwords to generate")
	noUpper := fs.Bool("no-upper", false, "Exclude uppercase letters")
	noLower := fs.Bool("no-lower", false, "Exclude lowercase letters")
	noDigits := fs.Bool("no-digits", false, "Exclude digits")
	noSpecial := fs.Bool("no-special", false, "Exclude special characters")
	exclude := fs.String("exclude", "", "Characters to exclude from generation")

	// Short flags
	fs.BoolVar(generate, "g", false, "Generate mode")
	fs.IntVar(length, "l", 16, "Password length")
	fs.IntVar(count, "n", 1, "Count")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns passwd [options] [password]

Analyze password strength or generate secure passwords.
Reads from arguments or stdin if no input provided.

Options:
  --generate, -g    Generate a secure password instead of analyzing
  --length, -l      Password length for generation (default: 16)
  --count, -n       Number of passwords to generate (default: 1)
  --no-upper        Exclude uppercase from generation
  --no-lower        Exclude lowercase from generation
  --no-digits       Exclude digits from generation
  --no-special      Exclude special characters from generation
  --exclude         Characters to exclude (e.g., "0OlI1")
  --help            Show this help message

Examples:
  nns passwd "MyP@ssw0rd"                # Analyze strength
  nns passwd -g                          # Generate 16-char password
  nns passwd -g -l 32                    # Generate 32-char password
  nns passwd -g -n 5                     # Generate 5 passwords
  nns passwd -g --no-special -l 20       # Alphanumeric only
  nns passwd -g --exclude "0OlI1"        # Exclude ambiguous chars
  echo "secret" | nns passwd             # Analyze from stdin
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Mode: generate
	if *generate {
		opts := passwd.GenerateOptions{
			Length:  *length,
			Upper:   !*noUpper,
			Lower:   !*noLower,
			Digits:  !*noDigits,
			Special: !*noSpecial,
			Exclude: *exclude,
			Count:   *count,
		}

		fmt.Printf("PASSWORD GENERATOR\n\n")

		passwords, err := passwd.GenerateMultiple(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		for i, pw := range passwords {
			if *count > 1 {
				fmt.Printf("  [%d] %s\n", i+1, pw)
			} else {
				fmt.Printf("  Password:  %s\n", pw)
			}
		}

		if *count == 1 {
			fmt.Println()
			fmt.Println("  Strength analysis:")
			analysis := passwd.Analyze(passwords[0])
			fmt.Print(passwd.FormatAnalysis(analysis))
		}
		return
	}

	// Mode: analyze
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
		fmt.Fprintf(os.Stderr, "Error: password required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	fmt.Printf("PASSWORD ANALYSIS\n\n")
	result := passwd.Analyze(input)
	fmt.Print(passwd.FormatAnalysis(result))
}
