package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/ssl"
)

func runSSL(args []string) {
	fs := flag.NewFlagSet("ssl", flag.ExitOnError)

	chainFlag := fs.Bool("chain", false, "Show full certificate chain")
	jsonFlag := fs.Bool("json", false, "Output in JSON format")
	expiryFlag := fs.Bool("expiry", false, "Show only expiry information")
	gradeFlag := fs.Bool("grade", false, "Show only security grade")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Connection timeout")

	fs.Usage = func() {
		fmt.Println(`Usage: nns ssl [HOST[:PORT]] [OPTIONS]

Analyze SSL/TLS certificates with security grading.

OPTIONS:
      --chain       Show full certificate chain
      --json        Output in JSON format (for scripting)
      --expiry      Show only expiry information
      --grade       Show only security grade
      --timeout     Connection timeout (default: 10s)
      --help        Show this help message

EXAMPLES:
  nns ssl google.com                 # Full analysis
  nns ssl example.com:8443           # Custom port
  nns ssl github.com --chain         # Show certificate chain
  nns ssl example.com --json         # JSON output
  nns ssl example.com --expiry       # Just expiry status
  nns ssl example.com --grade        # Just security grade

SECURITY GRADES:
  A+ : Excellent - No issues, TLS 1.2+, strong cipher
  A  : Good - Minor warnings only
  B  : Acceptable - Some issues
  C  : Weak - Multiple issues
  D  : Insecure - Critical issues
  F  : Fail - Expired, weak crypto, or self-signed`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: hostname required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host, port := ssl.ParseHostPort(fs.Arg(0))

	// Create analyzer
	analyzer := ssl.NewAnalyzer()
	analyzer.Timeout = *timeoutFlag

	result := analyzer.Analyze(host, port)

	if result.Error != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", result.Error)
		os.Exit(1)
	}

	// JSON output
	if *jsonFlag {
		jsonOutput, err := result.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(jsonOutput)
		return
	}

	// Expiry only
	if *expiryFlag {
		fmt.Printf("%s:%d — %s\n", host, port, result.ExpiryStatus())
		return
	}

	// Grade only
	if *gradeFlag {
		fmt.Printf("%s:%d — Grade: %s (Score: %d/100)\n",
			host, port, result.Security.Grade, result.Security.Score)
		return
	}

	// Full output
	printSSLResult(result, *chainFlag)
}

func printSSLResult(r *ssl.Result, showChain bool) {
	fmt.Printf("SSL/TLS Analysis for %s:%d\n", r.Host, r.Port)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Security Grade
	gradeColor := ""
	gradeReset := ""
	switch r.Security.Grade[0] {
	case 'A':
		gradeColor = "\033[32m" // Green
		gradeReset = "\033[0m"
	case 'B':
		gradeColor = "\033[33m" // Yellow
		gradeReset = "\033[0m"
	default:
		gradeColor = "\033[31m" // Red
		gradeReset = "\033[0m"
	}
	fmt.Printf("\n  Security Grade: %s%s%s (Score: %d/100)\n",
		gradeColor, r.Security.Grade, gradeReset, r.Security.Score)

	// Certificate info
	fmt.Println("\n─── Certificate ────────────────────────────────────────────────")
	fmt.Printf("  Subject:      %s\n", r.Certificate.Subject)
	fmt.Printf("  Issuer:       %s\n", r.Certificate.Issuer)
	fmt.Printf("  Serial:       %s\n", truncate(r.Certificate.SerialNumber, 40))
	fmt.Printf("  Valid From:   %s\n", r.Certificate.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Valid Until:  %s\n", r.Certificate.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Expiry:       %s\n", r.ExpiryStatus())

	// SANs
	if len(r.Certificate.SANs) > 0 {
		fmt.Printf("  SANs:         ")
		for i, san := range r.Certificate.SANs {
			if i > 0 {
				fmt.Printf(", ")
			}
			if i == 5 && len(r.Certificate.SANs) > 6 {
				fmt.Printf("... +%d more", len(r.Certificate.SANs)-5)
				break
			}
			fmt.Printf("%s", san)
		}
		fmt.Println()
	}

	// Crypto
	fmt.Println("\n─── Cryptography ───────────────────────────────────────────────")
	fmt.Printf("  Signature:    %s\n", r.Certificate.SignatureAlg)
	fmt.Printf("  Public Key:   %s (%d bits)\n", r.Certificate.PublicKeyAlg, r.Certificate.PublicKeySize)
	fmt.Printf("  Fingerprint:  %s\n", truncate(r.Certificate.Fingerprint, 32)+"...")

	// Connection
	fmt.Println("\n─── Connection ─────────────────────────────────────────────────")
	fmt.Printf("  TLS Version:  %s\n", r.Security.TLSVersion)
	fmt.Printf("  Cipher Suite: %s\n", r.Security.CipherSuite)
	fmt.Printf("  Connect Time: %v\n", r.ConnectTime.Round(time.Millisecond))

	// Issues
	if len(r.Security.Issues) > 0 {
		fmt.Println("\n─── Security Issues ────────────────────────────────────────────")
		for _, issue := range r.Security.Issues {
			icon := "ℹ"
			if issue.Severity == "warning" {
				icon = "⚠"
			} else if issue.Severity == "critical" {
				icon = "✗"
			}
			fmt.Printf("  %s %s\n", icon, issue.Message)
		}
	}

	// Chain
	if showChain && len(r.Chain.Certificates) > 1 {
		fmt.Println("\n─── Certificate Chain ──────────────────────────────────────────")
		for i, cert := range r.Chain.Certificates {
			role := "Leaf"
			if i > 0 && cert.IsCA {
				if i == len(r.Chain.Certificates)-1 {
					role = "Root"
				} else {
					role = "Intermediate"
				}
			}
			fmt.Printf("  [%d] %s (%s)\n", i, truncate(cert.Subject, 50), role)
		}
		fmt.Printf("\n  Chain Complete: %v | Trusted Root: %v\n",
			r.Chain.IsComplete, r.Chain.HasTrustedRoot)
	}

	fmt.Println()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
