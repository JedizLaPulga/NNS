// Package jwtutil provides JWT token decoding and security analysis.
package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Header represents a JWT header.
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

// Claims represents standard and custom JWT claims.
type Claims struct {
	// Standard claims
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  any    `json:"aud,omitempty"`
	ExpiresAt *int64 `json:"exp,omitempty"`
	NotBefore *int64 `json:"nbf,omitempty"`
	IssuedAt  *int64 `json:"iat,omitempty"`
	JWTID     string `json:"jti,omitempty"`

	// All claims (including custom)
	Raw map[string]any `json:"-"`
}

// Finding represents a security finding during JWT analysis.
type Finding struct {
	Severity string // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
	Message  string
}

// AnalysisResult holds the complete JWT analysis.
type AnalysisResult struct {
	Valid        bool
	Header       Header
	Claims       Claims
	Parts        int
	Signature    string
	Findings     []Finding
	ExpiryStatus string
	ExpiresIn    time.Duration
	Grade        string // A-F security grade
}

// Decode parses a JWT token string and performs security analysis.
func Decode(tokenStr string) (*AnalysisResult, error) {
	result := &AnalysisResult{
		Findings: make([]Finding, 0),
	}

	tokenStr = strings.TrimSpace(tokenStr)

	// Remove "Bearer " prefix if present
	if strings.HasPrefix(tokenStr, "Bearer ") {
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
	}

	parts := strings.Split(tokenStr, ".")
	result.Parts = len(parts)

	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("invalid JWT: expected 2 or 3 parts, got %d", len(parts))
	}

	// Decode header
	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}

	if err := json.Unmarshal(headerJSON, &result.Header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	// Decode claims (payload)
	claimsJSON, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}

	if err := json.Unmarshal(claimsJSON, &result.Claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	// Parse raw claims for custom fields
	result.Claims.Raw = make(map[string]any)
	json.Unmarshal(claimsJSON, &result.Claims.Raw)

	// Store signature info
	if len(parts) == 3 {
		result.Signature = parts[2]
	}

	result.Valid = true

	// Analyze security
	analyzeHeader(result)
	analyzeClaims(result)
	result.Grade = calculateGrade(result.Findings)

	return result, nil
}

// decodeSegment decodes a base64url-encoded JWT segment.
func decodeSegment(seg string) ([]byte, error) {
	// Add padding if necessary
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}

	return base64.URLEncoding.DecodeString(seg)
}

// analyzeHeader checks for known header vulnerabilities.
func analyzeHeader(r *AnalysisResult) {
	alg := strings.ToUpper(r.Header.Algorithm)

	switch alg {
	case "NONE", "":
		r.Findings = append(r.Findings, Finding{
			Severity: "CRITICAL",
			Message:  "Algorithm is 'none' — token is unsigned, trivially forgeable",
		})
	case "HS256":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "HMAC-SHA256 — symmetric signing (shared secret required)",
		})
	case "HS384":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "HMAC-SHA384 — symmetric signing",
		})
	case "HS512":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "HMAC-SHA512 — strong symmetric signing",
		})
	case "RS256":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "RSA-SHA256 — asymmetric signing",
		})
	case "RS384":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "RSA-SHA384 — asymmetric signing",
		})
	case "RS512":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "RSA-SHA512 — strong asymmetric signing",
		})
	case "ES256":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "ECDSA P-256 — modern asymmetric signing",
		})
	case "ES384":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "ECDSA P-384 — strong modern asymmetric signing",
		})
	case "ES512":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  "ECDSA P-521 — strongest ECDSA signing",
		})
	case "PS256", "PS384", "PS512":
		r.Findings = append(r.Findings, Finding{
			Severity: "INFO",
			Message:  fmt.Sprintf("%s — RSA-PSS signing (recommended over RS*)", alg),
		})
	default:
		r.Findings = append(r.Findings, Finding{
			Severity: "MEDIUM",
			Message:  fmt.Sprintf("Unknown algorithm: %s", r.Header.Algorithm),
		})
	}

	if r.Header.Type != "" && strings.ToUpper(r.Header.Type) != "JWT" {
		r.Findings = append(r.Findings, Finding{
			Severity: "LOW",
			Message:  fmt.Sprintf("Non-standard type: %s", r.Header.Type),
		})
	}

	if len(r.Parts) < 3 {
		r.Findings = append(r.Findings, Finding{
			Severity: "HIGH",
			Message:  "Token has no signature segment",
		})
	}
}

// analyzeClaims checks for claim-related issues.
func analyzeClaims(r *AnalysisResult) {
	now := time.Now()

	// Check expiration
	if r.Claims.ExpiresAt != nil {
		expiry := time.Unix(*r.Claims.ExpiresAt, 0)
		if now.After(expiry) {
			r.ExpiryStatus = "EXPIRED"
			r.ExpiresIn = now.Sub(expiry)
			r.Findings = append(r.Findings, Finding{
				Severity: "HIGH",
				Message:  fmt.Sprintf("Token expired %v ago (at %s)", r.ExpiresIn.Round(time.Second), expiry.Format(time.RFC3339)),
			})
		} else {
			r.ExpiresIn = expiry.Sub(now)
			r.ExpiryStatus = "VALID"

			if r.ExpiresIn < 5*time.Minute {
				r.Findings = append(r.Findings, Finding{
					Severity: "MEDIUM",
					Message:  fmt.Sprintf("Token expires in %v", r.ExpiresIn.Round(time.Second)),
				})
			} else if r.ExpiresIn > 365*24*time.Hour {
				r.Findings = append(r.Findings, Finding{
					Severity: "MEDIUM",
					Message:  fmt.Sprintf("Token has very long expiry: %v", r.ExpiresIn.Round(time.Hour)),
				})
			} else {
				r.Findings = append(r.Findings, Finding{
					Severity: "INFO",
					Message:  fmt.Sprintf("Token expires in %v", r.ExpiresIn.Round(time.Second)),
				})
			}
		}
	} else {
		r.ExpiryStatus = "NO_EXPIRY"
		r.Findings = append(r.Findings, Finding{
			Severity: "MEDIUM",
			Message:  "Token has no expiration claim (exp) — never expires",
		})
	}

	// Check nbf (not before)
	if r.Claims.NotBefore != nil {
		nbf := time.Unix(*r.Claims.NotBefore, 0)
		if now.Before(nbf) {
			r.Findings = append(r.Findings, Finding{
				Severity: "MEDIUM",
				Message:  fmt.Sprintf("Token not valid until %s", nbf.Format(time.RFC3339)),
			})
		}
	}

	// Check iat (issued at)
	if r.Claims.IssuedAt != nil {
		iat := time.Unix(*r.Claims.IssuedAt, 0)
		if now.Before(iat.Add(-5 * time.Minute)) {
			r.Findings = append(r.Findings, Finding{
				Severity: "LOW",
				Message:  fmt.Sprintf("Token issued in the future: %s", iat.Format(time.RFC3339)),
			})
		}
	}

	// Check for missing standard claims
	if r.Claims.Issuer == "" {
		r.Findings = append(r.Findings, Finding{
			Severity: "LOW",
			Message:  "No issuer claim (iss) — origin unclear",
		})
	}

	if r.Claims.Subject == "" {
		r.Findings = append(r.Findings, Finding{
			Severity: "LOW",
			Message:  "No subject claim (sub)",
		})
	}

	// Check for sensitive data in claims
	sensitiveKeys := []string{"password", "secret", "api_key", "apikey", "credit_card", "ssn", "token"}
	for key := range r.Claims.Raw {
		lower := strings.ToLower(key)
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(lower, sensitive) {
				r.Findings = append(r.Findings, Finding{
					Severity: "HIGH",
					Message:  fmt.Sprintf("Potentially sensitive data in claims: %q", key),
				})
			}
		}
	}
}

// calculateGrade calculates an overall security grade.
func calculateGrade(findings []Finding) string {
	criticals := 0
	highs := 0
	mediums := 0

	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			criticals++
		case "HIGH":
			highs++
		case "MEDIUM":
			mediums++
		}
	}

	switch {
	case criticals > 0:
		return "F"
	case highs > 1:
		return "D"
	case highs > 0:
		return "C"
	case mediums > 1:
		return "C"
	case mediums > 0:
		return "B"
	default:
		return "A"
	}
}

// FormatResult returns a human-readable formatted analysis.
func FormatResult(r *AnalysisResult) string {
	var sb strings.Builder

	sb.WriteString("JWT TOKEN ANALYSIS\n")
	sb.WriteString("══════════════════\n\n")

	// Header
	sb.WriteString("📋 Header\n")
	sb.WriteString(fmt.Sprintf("  Algorithm:  %s\n", r.Header.Algorithm))
	sb.WriteString(fmt.Sprintf("  Type:       %s\n", r.Header.Type))
	if r.Header.KeyID != "" {
		sb.WriteString(fmt.Sprintf("  Key ID:     %s\n", r.Header.KeyID))
	}

	// Claims
	sb.WriteString("\n📦 Claims\n")
	if r.Claims.Issuer != "" {
		sb.WriteString(fmt.Sprintf("  Issuer:     %s\n", r.Claims.Issuer))
	}
	if r.Claims.Subject != "" {
		sb.WriteString(fmt.Sprintf("  Subject:    %s\n", r.Claims.Subject))
	}
	if r.Claims.Audience != nil {
		sb.WriteString(fmt.Sprintf("  Audience:   %v\n", r.Claims.Audience))
	}
	if r.Claims.JWTID != "" {
		sb.WriteString(fmt.Sprintf("  JWT ID:     %s\n", r.Claims.JWTID))
	}

	// Times
	if r.Claims.IssuedAt != nil {
		iat := time.Unix(*r.Claims.IssuedAt, 0)
		sb.WriteString(fmt.Sprintf("  Issued At:  %s\n", iat.Format(time.RFC3339)))
	}
	if r.Claims.ExpiresAt != nil {
		exp := time.Unix(*r.Claims.ExpiresAt, 0)
		sb.WriteString(fmt.Sprintf("  Expires At: %s\n", exp.Format(time.RFC3339)))
	}
	if r.Claims.NotBefore != nil {
		nbf := time.Unix(*r.Claims.NotBefore, 0)
		sb.WriteString(fmt.Sprintf("  Not Before: %s\n", nbf.Format(time.RFC3339)))
	}

	// Expiry status
	sb.WriteString(fmt.Sprintf("\n⏱  Expiry: %s\n", formatExpiry(r)))

	// Custom claims
	customCount := 0
	for key := range r.Claims.Raw {
		switch key {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
			continue
		default:
			customCount++
		}
	}
	if customCount > 0 {
		sb.WriteString(fmt.Sprintf("\n🔧 Custom Claims (%d)\n", customCount))
		for key, val := range r.Claims.Raw {
			switch key {
			case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
				continue
			}
			valStr := fmt.Sprintf("%v", val)
			if len(valStr) > 80 {
				valStr = valStr[:77] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %-14s %s\n", key+":", valStr))
		}
	}

	// Security findings
	sb.WriteString(fmt.Sprintf("\n🔒 Security Analysis (Grade: %s)\n", gradeIcon(r.Grade)))
	for _, f := range r.Findings {
		sb.WriteString(fmt.Sprintf("  %s %s\n", severityIcon(f.Severity), f.Message))
	}

	return sb.String()
}

func formatExpiry(r *AnalysisResult) string {
	switch r.ExpiryStatus {
	case "EXPIRED":
		return fmt.Sprintf("🔴 EXPIRED (%v ago)", r.ExpiresIn.Round(time.Second))
	case "VALID":
		return fmt.Sprintf("🟢 Valid (expires in %v)", r.ExpiresIn.Round(time.Second))
	case "NO_EXPIRY":
		return "🟡 No expiration set"
	default:
		return "Unknown"
	}
}

func severityIcon(sev string) string {
	switch sev {
	case "CRITICAL":
		return "🔴 CRITICAL:"
	case "HIGH":
		return "🟠 HIGH:    "
	case "MEDIUM":
		return "🟡 MEDIUM:  "
	case "LOW":
		return "🔵 LOW:     "
	case "INFO":
		return "ℹ️  INFO:    "
	default:
		return "  " + sev + ":"
	}
}

func gradeIcon(grade string) string {
	switch grade {
	case "A":
		return "🟢 A"
	case "B":
		return "🟢 B"
	case "C":
		return "🟡 C"
	case "D":
		return "🟠 D"
	case "F":
		return "🔴 F"
	default:
		return grade
	}
}
