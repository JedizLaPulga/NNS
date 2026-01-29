package tlscheck

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestNewChecker(t *testing.T) {
	checker := NewChecker("example.com", 443)

	if checker.Host != "example.com" {
		t.Errorf("expected host 'example.com', got '%s'", checker.Host)
	}
	if checker.Port != 443 {
		t.Errorf("expected port 443, got %d", checker.Port)
	}
	if checker.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", checker.Timeout)
	}
	if checker.WarningDays != 30 {
		t.Errorf("expected warning days 30, got %d", checker.WarningDays)
	}
	if checker.CriticalDays != 7 {
		t.Errorf("expected critical days 7, got %d", checker.CriticalDays)
	}
	if checker.ServerName != "example.com" {
		t.Errorf("expected server name 'example.com', got '%s'", checker.ServerName)
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0000, "Unknown (0x0000)"},
	}

	for _, tt := range tests {
		result := tlsVersionString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionString(0x%04x) = %s, want %s", tt.version, result, tt.expected)
		}
	}
}

func TestIsWeakSignature(t *testing.T) {
	tests := []struct {
		alg    string
		isWeak bool
	}{
		{"SHA256WithRSA", false},
		{"SHA384WithRSA", false},
		{"SHA512WithRSA", false},
		{"MD5WithRSA", true},
		{"SHA1WithRSA", true},
		{"MD2WithRSA", true},
		{"ECDSAWithSHA256", false},
	}

	for _, tt := range tests {
		result := isWeakSignature(tt.alg)
		if result != tt.isWeak {
			t.Errorf("isWeakSignature(%s) = %v, want %v", tt.alg, result, tt.isWeak)
		}
	}
}

func TestParseKeyUsage(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	result := parseKeyUsage(usage)

	if len(result) != 2 {
		t.Errorf("expected 2 usages, got %d", len(result))
	}

	hasDigSig := false
	hasKeyEnc := false
	for _, u := range result {
		if u == "Digital Signature" {
			hasDigSig = true
		}
		if u == "Key Encipherment" {
			hasKeyEnc = true
		}
	}

	if !hasDigSig {
		t.Error("expected 'Digital Signature' in usages")
	}
	if !hasKeyEnc {
		t.Error("expected 'Key Encipherment' in usages")
	}
}

func TestParseExtKeyUsage(t *testing.T) {
	eku := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	}

	result := parseExtKeyUsage(eku)

	if len(result) != 2 {
		t.Errorf("expected 2 extended usages, got %d", len(result))
	}

	hasServer := false
	hasClient := false
	for _, u := range result {
		if u == "Server Authentication" {
			hasServer = true
		}
		if u == "Client Authentication" {
			hasClient = true
		}
	}

	if !hasServer {
		t.Error("expected 'Server Authentication' in usages")
	}
	if !hasClient {
		t.Error("expected 'Client Authentication' in usages")
	}
}

func TestSHA256Fingerprint(t *testing.T) {
	data := []byte("test data")
	fingerprint := sha256Fingerprint(data)

	if len(fingerprint) == 0 {
		t.Error("expected non-empty fingerprint")
	}

	// SHA-256 produces 32 bytes = 64 hex chars + 31 colons = 95 chars
	if len(fingerprint) != 95 {
		t.Errorf("expected fingerprint length 95, got %d", len(fingerprint))
	}
}

func TestCalculateGrade(t *testing.T) {
	checker := NewChecker("example.com", 443)

	tests := []struct {
		name       string
		tlsVersion string
		chainValid bool
		warnings   []string
		security   []string
		wantGrade  string
	}{
		{
			name:       "perfect TLS 1.3",
			tlsVersion: "TLS 1.3",
			chainValid: true,
			warnings:   []string{},
			security:   []string{},
			wantGrade:  "A+",
		},
		{
			name:       "TLS 1.2",
			tlsVersion: "TLS 1.2",
			chainValid: true,
			warnings:   []string{},
			security:   []string{},
			wantGrade:  "A+",
		},
		{
			name:       "TLS 1.0",
			tlsVersion: "TLS 1.0",
			chainValid: true,
			warnings:   []string{},
			security:   []string{},
			wantGrade:  "C", // 100 - 50 = 50 -> C
		},
		{
			name:       "invalid chain",
			tlsVersion: "TLS 1.3",
			chainValid: false,
			warnings:   []string{},
			security:   []string{},
			wantGrade:  "D", // 100 - 40 = 60 -> D
		},
		{
			name:       "expired cert",
			tlsVersion: "TLS 1.3",
			chainValid: true,
			warnings:   []string{"Certificate EXPIRED"},
			security:   []string{},
			wantGrade:  "C", // 100 - 50 = 50 -> C
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ChainResult{
				TLSVersion:       tt.tlsVersion,
				ChainValid:       tt.chainValid,
				ExpiryWarnings:   tt.warnings,
				SecurityWarnings: tt.security,
			}

			grade := checker.calculateGrade(result)
			if grade != tt.wantGrade {
				t.Errorf("calculateGrade() = %s, want %s", grade, tt.wantGrade)
			}
		})
	}
}

// TestCheckConnectionError tests error handling when connection fails.
func TestCheckConnectionError(t *testing.T) {
	checker := NewChecker("invalid-host-that-does-not-exist.local", 443)
	checker.Timeout = 1 * time.Second

	_, err := checker.Check()
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

// TestCheckWithRealServer tests against a real TLS server (localhost if available).
func TestCheckWithRealServer(t *testing.T) {
	// Try to connect to a local server if available, skip otherwise
	conn, err := net.DialTimeout("tcp", "localhost:443", 1*time.Second)
	if err != nil {
		t.Skip("No local TLS server on port 443")
	}
	conn.Close()

	checker := NewChecker("localhost", 443)
	checker.SkipVerify = true
	checker.Timeout = 5 * time.Second

	result, err := checker.Check()
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if result.TLSVersion == "" {
		t.Error("expected TLS version to be set")
	}
	if result.CipherSuite == "" {
		t.Error("expected cipher suite to be set")
	}
	if len(result.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}
}

func TestCertificateFields(t *testing.T) {
	cert := Certificate{
		Subject:         "example.com",
		Issuer:          "Root CA",
		DaysUntilExpiry: 30,
		IsCA:            false,
		IsSelfSigned:    false,
	}

	if cert.Subject != "example.com" {
		t.Errorf("expected subject 'example.com', got '%s'", cert.Subject)
	}
	if cert.DaysUntilExpiry != 30 {
		t.Errorf("expected 30 days until expiry, got %d", cert.DaysUntilExpiry)
	}
}
