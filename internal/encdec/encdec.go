// Package encdec provides encoding and decoding utilities for common formats.
package encdec

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Format represents a supported encoding format.
type Format string

const (
	FormatBase64    Format = "base64"
	FormatBase64URL Format = "base64url"
	FormatHex       Format = "hex"
	FormatURL       Format = "url"
	FormatBinary    Format = "binary"
)

// AllFormats returns all supported encoding formats.
func AllFormats() []Format {
	return []Format{FormatBase64, FormatBase64URL, FormatHex, FormatURL, FormatBinary}
}

// Result holds the result of an encode or decode operation.
type Result struct {
	Input   string `json:"input"`
	Output  string `json:"output"`
	Format  Format `json:"format"`
	Encode  bool   `json:"encode"`
	Valid   bool   `json:"valid"`
	InSize  int    `json:"input_size"`
	OutSize int    `json:"output_size"`
	Error   string `json:"error,omitempty"`
}

// Encode encodes the input string using the specified format.
func Encode(input string, format Format) Result {
	r := Result{
		Input:  input,
		Format: format,
		Encode: true,
		InSize: len(input),
		Valid:  true,
	}

	switch format {
	case FormatBase64:
		r.Output = base64.StdEncoding.EncodeToString([]byte(input))
	case FormatBase64URL:
		r.Output = base64.URLEncoding.EncodeToString([]byte(input))
	case FormatHex:
		r.Output = hex.EncodeToString([]byte(input))
	case FormatURL:
		r.Output = url.QueryEscape(input)
	case FormatBinary:
		r.Output = toBinary(input)
	default:
		r.Valid = false
		r.Error = fmt.Sprintf("unsupported format: %s", format)
		return r
	}

	r.OutSize = len(r.Output)
	return r
}

// Decode decodes the input string using the specified format.
func Decode(input string, format Format) Result {
	r := Result{
		Input:  input,
		Format: format,
		Encode: false,
		InSize: len(input),
	}

	switch format {
	case FormatBase64:
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			r.Valid = false
			r.Error = fmt.Sprintf("invalid base64: %v", err)
			return r
		}
		r.Output = string(decoded)
		r.Valid = true
	case FormatBase64URL:
		decoded, err := base64.URLEncoding.DecodeString(input)
		if err != nil {
			r.Valid = false
			r.Error = fmt.Sprintf("invalid base64url: %v", err)
			return r
		}
		r.Output = string(decoded)
		r.Valid = true
	case FormatHex:
		decoded, err := hex.DecodeString(input)
		if err != nil {
			r.Valid = false
			r.Error = fmt.Sprintf("invalid hex: %v", err)
			return r
		}
		r.Output = string(decoded)
		r.Valid = true
	case FormatURL:
		decoded, err := url.QueryUnescape(input)
		if err != nil {
			r.Valid = false
			r.Error = fmt.Sprintf("invalid URL encoding: %v", err)
			return r
		}
		r.Output = decoded
		r.Valid = true
	case FormatBinary:
		decoded, err := fromBinary(input)
		if err != nil {
			r.Valid = false
			r.Error = fmt.Sprintf("invalid binary: %v", err)
			return r
		}
		r.Output = decoded
		r.Valid = true
	default:
		r.Valid = false
		r.Error = fmt.Sprintf("unsupported format: %s", format)
		return r
	}

	r.OutSize = len(r.Output)
	return r
}

// EncodeAll encodes the input in all supported formats.
func EncodeAll(input string) []Result {
	results := make([]Result, 0, len(AllFormats()))
	for _, f := range AllFormats() {
		results = append(results, Encode(input, f))
	}
	return results
}

// DetectFormat attempts to identify the encoding format of the input.
func DetectFormat(input string) []Format {
	var detected []Format

	// Check hex: even length, all hex chars
	if len(input)%2 == 0 && len(input) > 0 && isHex(input) {
		detected = append(detected, FormatHex)
	}

	// Check base64: standard alphabet
	if len(input) > 0 && len(input)%4 == 0 {
		if _, err := base64.StdEncoding.DecodeString(input); err == nil {
			detected = append(detected, FormatBase64)
		}
	}

	// Check base64url
	if len(input) > 0 && len(input)%4 == 0 {
		if _, err := base64.URLEncoding.DecodeString(input); err == nil {
			if strings.ContainsAny(input, "-_") {
				detected = append(detected, FormatBase64URL)
			}
		}
	}

	// Check URL encoding: contains % sequences
	if strings.Contains(input, "%") {
		if _, err := url.QueryUnescape(input); err == nil {
			detected = append(detected, FormatURL)
		}
	}

	// Check binary: only 0, 1, and spaces
	if len(input) > 0 && isBinaryString(input) {
		detected = append(detected, FormatBinary)
	}

	return detected
}

// FormatResult returns a human-readable string for a single result.
func FormatResult(r Result) string {
	var sb strings.Builder
	op := "Encode"
	if !r.Encode {
		op = "Decode"
	}

	sb.WriteString(fmt.Sprintf("  Operation:  %s\n", op))
	sb.WriteString(fmt.Sprintf("  Format:     %s\n", r.Format))
	sb.WriteString(fmt.Sprintf("  Valid:      %v\n", r.Valid))

	if r.Error != "" {
		sb.WriteString(fmt.Sprintf("  Error:      %s\n", r.Error))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("  Input:      %s\n", truncate(r.Input, 80)))
	sb.WriteString(fmt.Sprintf("  Output:     %s\n", truncate(r.Output, 80)))
	sb.WriteString(fmt.Sprintf("  In size:    %d bytes\n", r.InSize))
	sb.WriteString(fmt.Sprintf("  Out size:   %d bytes\n", r.OutSize))

	ratio := float64(r.OutSize) / float64(r.InSize)
	if r.InSize > 0 {
		sb.WriteString(fmt.Sprintf("  Ratio:      %.2fx\n", ratio))
	}

	return sb.String()
}

// FormatDetection returns a human-readable string for detected formats.
func FormatDetection(input string, formats []Format) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Input:      %s\n", truncate(input, 80)))
	sb.WriteString(fmt.Sprintf("  Length:     %d bytes\n", len(input)))

	if len(formats) == 0 {
		sb.WriteString("  Detected:   (none - could be plain text)\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("  Possible formats:\n"))
	for _, f := range formats {
		r := Decode(input, f)
		if r.Valid && utf8.ValidString(r.Output) {
			sb.WriteString(fmt.Sprintf("    %-10s → %s\n", f, truncate(r.Output, 60)))
		} else {
			sb.WriteString(fmt.Sprintf("    %-10s → (binary data, %d bytes)\n", f, r.OutSize))
		}
	}

	return sb.String()
}

func toBinary(input string) string {
	var parts []string
	for _, b := range []byte(input) {
		parts = append(parts, fmt.Sprintf("%08b", b))
	}
	return strings.Join(parts, " ")
}

func fromBinary(input string) (string, error) {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty binary string")
	}

	var result []byte
	for _, part := range parts {
		if len(part) != 8 {
			return "", fmt.Errorf("invalid binary octet: %q (must be 8 bits)", part)
		}
		var b byte
		for _, c := range part {
			b <<= 1
			switch c {
			case '1':
				b |= 1
			case '0':
				// nothing
			default:
				return "", fmt.Errorf("invalid binary character: %c", c)
			}
		}
		result = append(result, b)
	}
	return string(result), nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isBinaryString(s string) bool {
	for _, c := range s {
		if c != '0' && c != '1' && c != ' ' {
			return false
		}
	}
	return true
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
