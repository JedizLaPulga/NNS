// Package cli provides utilities for building command-line interfaces.
package cli

import (
	"fmt"
	"os"
	"strings"
)

// ExitCode represents standard exit codes
const (
	ExitSuccess = 0
	ExitError   = 1
)

// PrintError prints an error message to stderr
func PrintError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
}

// PrintWarning prints a warning message to stderr
func PrintWarning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

// PrintInfo prints an informational message to stdout
func PrintInfo(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// FormatTable formats data as a simple table (to be expanded)
func FormatTable(headers []string, rows [][]string) string {
	var sb strings.Builder

	// Print headers
	sb.WriteString(strings.Join(headers, "\t"))
	sb.WriteString("\n")

	// Print separator
	for range headers {
		sb.WriteString("--------\t")
	}
	sb.WriteString("\n")

	// Print rows
	for _, row := range rows {
		sb.WriteString(strings.Join(row, "\t"))
		sb.WriteString("\n")
	}

	return sb.String()
}
