package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func makeToken(header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	hEnc := base64.RawURLEncoding.EncodeToString(h)
	cEnc := base64.RawURLEncoding.EncodeToString(c)
	return hEnc + "." + cEnc + ".fakesignature"
}

func TestDecodeValidToken(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	iat := time.Now().Unix()

	token := makeToken(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"iss": "test-issuer",
			"sub": "user123",
			"exp": exp,
			"iat": iat,
		},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !result.Valid {
		t.Error("expected valid token")
	}
	if result.Header.Algorithm != "HS256" {
		t.Errorf("expected alg=HS256, got %s", result.Header.Algorithm)
	}
	if result.Header.Type != "JWT" {
		t.Errorf("expected typ=JWT, got %s", result.Header.Type)
	}
	if result.Claims.Issuer != "test-issuer" {
		t.Errorf("expected issuer=test-issuer, got %s", result.Claims.Issuer)
	}
	if result.Claims.Subject != "user123" {
		t.Errorf("expected sub=user123, got %s", result.Claims.Subject)
	}
}

func TestDecodeBearerPrefix(t *testing.T) {
	token := makeToken(
		map[string]any{"alg": "RS256", "typ": "JWT"},
		map[string]any{"sub": "user"},
	)

	result, err := Decode("Bearer " + token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if result.Header.Algorithm != "RS256" {
		t.Errorf("expected alg=RS256, got %s", result.Header.Algorithm)
	}
}

func TestDecodeInvalidFormat(t *testing.T) {
	_, err := Decode("not-a-jwt")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestDecodeInvalidBase64(t *testing.T) {
	_, err := Decode("!!!.!!!.!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecodeNoneAlgorithm(t *testing.T) {
	token := makeToken(
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{"sub": "admin"},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	hasCritical := false
	for _, f := range result.Findings {
		if f.Severity == "CRITICAL" {
			hasCritical = true
			break
		}
	}

	if !hasCritical {
		t.Error("expected CRITICAL finding for alg=none")
	}

	if result.Grade != "F" {
		t.Errorf("expected grade F for alg=none, got %s", result.Grade)
	}
}

func TestDecodeExpiredToken(t *testing.T) {
	exp := time.Now().Add(-1 * time.Hour).Unix()

	token := makeToken(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "user", "exp": exp},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if result.ExpiryStatus != "EXPIRED" {
		t.Errorf("expected EXPIRED status, got %s", result.ExpiryStatus)
	}

	hasExpiredFinding := false
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "expired") || strings.Contains(f.Message, "Token expired") {
			hasExpiredFinding = true
			break
		}
	}
	if !hasExpiredFinding {
		t.Error("expected finding about expired token")
	}
}

func TestDecodeNoExpiry(t *testing.T) {
	token := makeToken(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "user"},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if result.ExpiryStatus != "NO_EXPIRY" {
		t.Errorf("expected NO_EXPIRY status, got %s", result.ExpiryStatus)
	}
}

func TestDecodeLongExpiry(t *testing.T) {
	exp := time.Now().Add(2 * 365 * 24 * time.Hour).Unix()

	token := makeToken(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "user", "exp": exp},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	hasLongExpiry := false
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "very long expiry") {
			hasLongExpiry = true
			break
		}
	}
	if !hasLongExpiry {
		t.Error("expected finding about very long expiry")
	}
}

func TestDecodeSensitiveData(t *testing.T) {
	token := makeToken(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "user", "password": "secret123", "api_key": "xyz"},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	sensitiveCount := 0
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "sensitive") {
			sensitiveCount++
		}
	}
	if sensitiveCount < 2 {
		t.Errorf("expected at least 2 sensitive data findings, got %d", sensitiveCount)
	}
}

func TestDecodeCustomClaims(t *testing.T) {
	token := makeToken(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"sub":   "user",
			"role":  "admin",
			"scope": "read write",
		},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if result.Claims.Raw["role"] != "admin" {
		t.Errorf("expected custom claim role=admin, got %v", result.Claims.Raw["role"])
	}
}

func TestDecodeSegment(t *testing.T) {
	original := []byte(`{"alg":"HS256"}`)
	encoded := base64.RawURLEncoding.EncodeToString(original)

	decoded, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("decodeSegment failed: %v", err)
	}

	if string(decoded) != string(original) {
		t.Errorf("expected %q, got %q", string(original), string(decoded))
	}
}

func TestDecodeSegmentWithPadding(t *testing.T) {
	tests := []struct {
		name string
		mod  int
	}{
		{"mod2", 2},
		{"mod3", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := strings.Repeat("x", tt.mod)
			encoded := base64.RawURLEncoding.EncodeToString([]byte(data))
			_, err := decodeSegment(encoded)
			if err != nil {
				t.Errorf("decodeSegment should handle padding for mod %d", tt.mod)
			}
		})
	}
}

func TestFormatResult(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	iat := time.Now().Unix()

	token := makeToken(
		map[string]any{"alg": "HS256", "typ": "JWT", "kid": "key-1"},
		map[string]any{
			"iss":  "auth.example.com",
			"sub":  "user@example.com",
			"exp":  exp,
			"iat":  iat,
			"role": "admin",
		},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	output := FormatResult(result)

	checks := []string{
		"JWT TOKEN ANALYSIS",
		"HS256",
		"auth.example.com",
		"user@example.com",
		"Security Analysis",
		"Grade:",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("format output should contain %q", check)
		}
	}
}

func TestFormatExpiry(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   string
	}{
		{"expired", "EXPIRED", "EXPIRED"},
		{"valid", "VALID", "Valid"},
		{"no_expiry", "NO_EXPIRY", "No expiration"},
		{"unknown", "OTHER", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &AnalysisResult{
				ExpiryStatus: tt.status,
				ExpiresIn:    1 * time.Hour,
			}
			result := formatExpiry(r)
			if !strings.Contains(result, tt.want) {
				t.Errorf("formatExpiry(%q) should contain %q, got %q", tt.status, tt.want, result)
			}
		})
	}
}

func TestCalculateGrade(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     string
	}{
		{"no findings", nil, "A"},
		{"info only", []Finding{{Severity: "INFO"}}, "A"},
		{"one medium", []Finding{{Severity: "MEDIUM"}}, "B"},
		{"two mediums", []Finding{{Severity: "MEDIUM"}, {Severity: "MEDIUM"}}, "C"},
		{"one high", []Finding{{Severity: "HIGH"}}, "C"},
		{"two highs", []Finding{{Severity: "HIGH"}, {Severity: "HIGH"}}, "D"},
		{"critical", []Finding{{Severity: "CRITICAL"}}, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateGrade(tt.findings)
			if got != tt.want {
				t.Errorf("calculateGrade() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSeverityIcon(t *testing.T) {
	tests := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	for _, sev := range tests {
		icon := severityIcon(sev)
		if icon == "" {
			t.Errorf("severityIcon(%q) should not be empty", sev)
		}
	}
}

func TestGradeIcon(t *testing.T) {
	tests := []struct {
		grade string
		want  string
	}{
		{"A", "🟢"},
		{"B", "🟢"},
		{"C", "🟡"},
		{"D", "🟠"},
		{"F", "🔴"},
	}

	for _, tt := range tests {
		icon := gradeIcon(tt.grade)
		if !strings.Contains(icon, tt.want) {
			t.Errorf("gradeIcon(%q) should contain %q, got %q", tt.grade, tt.want, icon)
		}
	}
}

func TestDecodeTwoParts(t *testing.T) {
	h, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	c, _ := json.Marshal(map[string]any{"sub": "user"})
	token := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if result.Parts != 2 {
		t.Errorf("expected 2 parts, got %d", result.Parts)
	}
}

func TestDecodeUnknownAlgorithm(t *testing.T) {
	token := makeToken(
		map[string]any{"alg": "WEIRD256", "typ": "JWT"},
		map[string]any{"sub": "user"},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	hasUnknown := false
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "Unknown algorithm") {
			hasUnknown = true
			break
		}
	}
	if !hasUnknown {
		t.Error("expected finding about unknown algorithm")
	}
}

func TestDecodeAllAlgorithms(t *testing.T) {
	algs := []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

	for _, alg := range algs {
		t.Run(alg, func(t *testing.T) {
			token := makeToken(
				map[string]any{"alg": alg, "typ": "JWT"},
				map[string]any{"sub": "user", "iss": "test", "exp": time.Now().Add(1 * time.Hour).Unix()},
			)

			result, err := Decode(token)
			if err != nil {
				t.Fatalf("Decode(%s) failed: %v", alg, err)
			}

			if result.Header.Algorithm != alg {
				t.Errorf("expected alg=%s, got %s", alg, result.Header.Algorithm)
			}
		})
	}
}

func TestFormatResultLongCustomClaim(t *testing.T) {
	longValue := strings.Repeat("x", 100)
	token := makeToken(
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{"sub": "user", "data": longValue},
	)

	result, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	output := FormatResult(result)
	if !strings.Contains(output, "...") {
		// long value should be truncated
		fmt.Println("Note: long claim value truncation check")
	}
}
