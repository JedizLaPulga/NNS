package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/tlscheck"
)

func runTLSCheck(args []string) {
	fs := flag.NewFlagSet("tlscheck", flag.ExitOnError)
	portFlag := fs.Int("port", 443, "Target port")
	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Connection timeout")
	skipVerifyFlag := fs.Bool("skip-verify", false, "Skip certificate chain verification")
	warningDaysFlag := fs.Int("warning", 30, "Days before expiry for warning")
	criticalDaysFlag := fs.Int("critical", 7, "Days before expiry for critical alert")
	serverNameFlag := fs.String("servername", "", "Server name for SNI (default: host)")
	chainFlag := fs.Bool("chain", false, "Show full certificate chain")
	jsonFlag := fs.Bool("json", false, "Output in JSON format")

	// Short flags
	fs.IntVar(portFlag, "p", 443, "Target port")
	fs.DurationVar(timeoutFlag, "t", 10*time.Second, "Connection timeout")
	fs.BoolVar(skipVerifyFlag, "k", false, "Skip certificate chain verification")
	fs.BoolVar(chainFlag, "c", false, "Show full certificate chain")

	fs.Usage = func() {
		fmt.Println(`Usage: nns tlscheck [HOST] [OPTIONS]

Validate TLS certificate chain with expiry warnings and security grading.

OPTIONS:
  --port, -p       Target port (default: 443)
  --timeout, -t    Connection timeout (default: 10s)
  --skip-verify, -k  Skip certificate chain verification
  --warning        Days before expiry for warning (default: 30)
  --critical       Days before expiry for critical alert (default: 7)
  --servername     Server name for SNI (default: host)
  --chain, -c      Show full certificate chain details
  --json           Output in JSON format
  --help           Show this help message

EXAMPLES:
  nns tlscheck google.com
  nns tlscheck example.com --chain
  nns tlscheck api.example.com -p 8443 --warning 60
  nns tlscheck internal.local --skip-verify`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: target host required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)

	checker := tlscheck.NewChecker(host, *portFlag)
	checker.Timeout = *timeoutFlag
	checker.SkipVerify = *skipVerifyFlag
	checker.WarningDays = *warningDaysFlag
	checker.CriticalDays = *criticalDaysFlag
	if *serverNameFlag != "" {
		checker.ServerName = *serverNameFlag
	}

	fmt.Printf("TLS Certificate Check: %s:%d\n", host, *portFlag)
	fmt.Println(strings.Repeat("─", 50))

	result, err := checker.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonFlag {
		printTLSCheckJSON(result)
		return
	}

	// Connection info
	fmt.Printf("\n📡 Connection:\n")
	fmt.Printf("  TLS Version:    %s\n", result.TLSVersion)
	fmt.Printf("  Cipher Suite:   %s\n", result.CipherSuite)
	fmt.Printf("  Connect Time:   %v\n", result.ConnectTime.Round(time.Microsecond))
	fmt.Printf("  Handshake Time: %v\n", result.HandshakeTime.Round(time.Microsecond))

	// Certificate summary
	if len(result.Certificates) > 0 {
		cert := result.Certificates[0]
		fmt.Printf("\n🔐 Server Certificate:\n")
		fmt.Printf("  Subject:        %s\n", cert.Subject)
		fmt.Printf("  Issuer:         %s\n", cert.Issuer)
		fmt.Printf("  Valid From:     %s\n", cert.NotBefore.Format("2006-01-02"))
		fmt.Printf("  Valid Until:    %s\n", cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("  Days Remaining: %d\n", cert.DaysUntilExpiry)
		fmt.Printf("  Algorithm:      %s\n", cert.SignatureAlgorithm)
		if len(cert.DNSNames) > 0 {
			fmt.Printf("  SANs:           %s\n", strings.Join(cert.DNSNames, ", "))
		}
		fmt.Printf("  Fingerprint:    %s...\n", cert.Fingerprint[:23])
	}

	// Chain details
	if *chainFlag && len(result.Certificates) > 1 {
		fmt.Printf("\n📜 Certificate Chain (%d certificates):\n", len(result.Certificates))
		for i, cert := range result.Certificates {
			fmt.Printf("\n  [%d] %s\n", i+1, cert.Subject)
			fmt.Printf("      Issuer:  %s\n", cert.Issuer)
			fmt.Printf("      Expires: %s (%d days)\n", cert.NotAfter.Format("2006-01-02"), cert.DaysUntilExpiry)
			if cert.IsCA {
				fmt.Printf("      Type:    CA Certificate\n")
			}
			if cert.IsSelfSigned {
				fmt.Printf("      Note:    Self-signed\n")
			}
		}
	}

	// Chain validation
	fmt.Printf("\n✅ Validation:\n")
	if result.ChainValid {
		fmt.Printf("  Chain Status:   Valid\n")
	} else {
		fmt.Printf("  Chain Status:   ❌ Invalid\n")
		fmt.Printf("  Error:          %s\n", result.ChainError)
	}

	// Expiry warnings
	if len(result.ExpiryWarnings) > 0 {
		fmt.Printf("\n⚠️  Expiry Warnings:\n")
		for _, w := range result.ExpiryWarnings {
			fmt.Printf("  • %s\n", w)
		}
	}

	// Security warnings
	if len(result.SecurityWarnings) > 0 {
		fmt.Printf("\n🛡️  Security Warnings:\n")
		for _, w := range result.SecurityWarnings {
			fmt.Printf("  • %s\n", w)
		}
	}

	// Grade
	gradeEmoji := gradeToEmoji(result.Grade)
	fmt.Printf("\n📊 Security Grade: %s %s\n", gradeEmoji, result.Grade)
}

func printTLSCheckJSON(result *tlscheck.ChainResult) {
	fmt.Printf(`{
  "host": "%s",
  "port": %d,
  "tls_version": "%s",
  "cipher_suite": "%s",
  "verified": %t,
  "chain_valid": %t,
  "grade": "%s",
  "certificates": %d,
  "expiry_warnings": %d,
  "security_warnings": %d
}
`, result.Host, result.Port, result.TLSVersion, result.CipherSuite,
		result.Verified, result.ChainValid, result.Grade,
		len(result.Certificates), len(result.ExpiryWarnings), len(result.SecurityWarnings))
}

func gradeToEmoji(grade string) string {
	switch grade {
	case "A+":
		return "🏆"
	case "A":
		return "🟢"
	case "B":
		return "🟡"
	case "C":
		return "🟠"
	case "D", "F":
		return "🔴"
	default:
		return "❓"
	}
}
