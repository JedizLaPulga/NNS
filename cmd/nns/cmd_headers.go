package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/headers"
)

func runHeaders(args []string) {
	fs := flag.NewFlagSet("headers", flag.ExitOnError)

	timeoutFlag := fs.Duration("timeout", 10*time.Second, "Request timeout")

	fs.Usage = func() {
		fmt.Println(`Usage: nns headers [URL] [OPTIONS]

Analyze HTTP security headers with scoring.

OPTIONS:
      --timeout    Request timeout (default: 10s)
      --help       Show this help message

EXAMPLES:
  nns headers google.com
  nns headers https://example.com`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: URL required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	url := fs.Arg(0)

	analyzer := headers.NewAnalyzer()
	analyzer.Timeout = *timeoutFlag

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	result, err := analyzer.Analyze(ctx, url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("Security Headers Analysis for %s\n", result.URL)
	fmt.Println("════════════════════════════════════════════════════════════════")

	// Grade
	gradeColor := ""
	gradeReset := ""
	switch result.Grade[0] {
	case 'A':
		gradeColor = "\033[32m"
		gradeReset = "\033[0m"
	case 'B':
		gradeColor = "\033[33m"
		gradeReset = "\033[0m"
	default:
		gradeColor = "\033[31m"
		gradeReset = "\033[0m"
	}
	fmt.Printf("\n  Grade: %s%s%s (Score: %d/100)\n", gradeColor, result.Grade, gradeReset, result.Score)

	// Present headers
	fmt.Println("\n─── Present Headers ────────────────────────────────────────────")
	present := result.GetPresentHeaders()
	if len(present) > 0 {
		for _, h := range present {
			value := result.Headers[h]
			if len(value) > 50 {
				value = value[:47] + "..."
			}
			fmt.Printf("  ✓ %-35s %s\n", h, value)
		}
	} else {
		fmt.Println("  None")
	}

	// Missing headers
	fmt.Println("\n─── Missing Headers ────────────────────────────────────────────")
	missing := result.GetMissingHeaders()
	if len(missing) > 0 {
		for _, h := range missing {
			fmt.Printf("  ✗ %s\n", h)
		}
	} else {
		fmt.Println("  None - Great job!")
	}

	// Issues
	if len(result.Issues) > 0 {
		fmt.Println("\n─── Security Issues ────────────────────────────────────────────")
		for _, issue := range result.Issues {
			icon := "ℹ"
			if issue.Severity == headers.SeverityWarning {
				icon = "⚠"
			} else if issue.Severity == headers.SeverityCritical {
				icon = "✗"
			}
			fmt.Printf("  %s [%s] %s\n", icon, issue.Header, issue.Message)
			if issue.Fix != "" {
				fmt.Printf("    Fix: %s\n", issue.Fix)
			}
		}
	}

	fmt.Printf("\n  Query Time: %v\n", result.Duration.Round(time.Millisecond))
}
