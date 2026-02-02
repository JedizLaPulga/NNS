package dnssec

import (
	"context"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Resolver != "8.8.8.8:53" {
		t.Errorf("Resolver = %s, want 8.8.8.8:53", opts.Resolver)
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", opts.Timeout)
	}
	if !opts.CheckExpiry {
		t.Error("CheckExpiry should be true")
	}
}

func TestNewValidator(t *testing.T) {
	v := NewValidator(DefaultOptions())
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.resolver == nil {
		t.Error("resolver not initialized")
	}
}

func TestValidationStatus(t *testing.T) {
	tests := []ValidationStatus{StatusSecure, StatusInsecure, StatusBogus, StatusIndeterminate}
	for _, s := range tests {
		if s == "" {
			t.Error("ValidationStatus should not be empty")
		}
	}
}

func TestAlgorithmNames(t *testing.T) {
	tests := []struct {
		alg      Algorithm
		expected string
	}{
		{AlgRSASHA256, "RSA/SHA-256"},
		{AlgECDSAP256, "ECDSA P-256/SHA-256"},
		{AlgED25519, "Ed25519"},
	}

	for _, tt := range tests {
		if name := AlgorithmNames[tt.alg]; name != tt.expected {
			t.Errorf("AlgorithmNames[%d] = %s, want %s", tt.alg, name, tt.expected)
		}
	}
}

func TestDigestNames(t *testing.T) {
	if DigestNames[DigestSHA256] != "SHA-256" {
		t.Error("DigestSHA256 name incorrect")
	}
	if DigestNames[DigestSHA384] != "SHA-384" {
		t.Error("DigestSHA384 name incorrect")
	}
}

func TestGetZoneHierarchy(t *testing.T) {
	v := NewValidator(DefaultOptions())

	zones := v.getZoneHierarchy("www.example.com")

	expected := []string{".", "com", "example.com", "www.example.com"}
	if len(zones) != len(expected) {
		t.Fatalf("got %d zones, want %d", len(zones), len(expected))
	}

	for i, z := range expected {
		if zones[i] != z {
			t.Errorf("zones[%d] = %s, want %s", i, zones[i], z)
		}
	}
}

func TestValidate(t *testing.T) {
	v := NewValidator(DefaultOptions())
	ctx := context.Background()

	result, err := v.Validate(ctx, "example.com")
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if result.Domain != "example.com" {
		t.Errorf("Domain = %s, want example.com", result.Domain)
	}

	if len(result.Chain) == 0 {
		t.Error("Chain should not be empty")
	}

	if result.TotalTime == 0 {
		t.Error("TotalTime should be set")
	}
}

func TestContainsAlgorithm(t *testing.T) {
	algs := []Algorithm{AlgRSASHA256, AlgECDSAP256}

	if !containsAlgorithm(algs, AlgRSASHA256) {
		t.Error("should contain RSA/SHA-256")
	}
	if containsAlgorithm(algs, AlgED25519) {
		t.Error("should not contain Ed25519")
	}
}

func TestGenerateKeyTag(t *testing.T) {
	tag1 := generateKeyTag("example.com", true)
	tag2 := generateKeyTag("example.com", false)
	tag3 := generateKeyTag("other.com", true)

	if tag1 == tag2 {
		t.Error("KSK and ZSK should have different tags")
	}
	if tag1 == tag3 {
		t.Error("different zones should have different tags")
	}
}

func TestCalculateScore(t *testing.T) {
	v := NewValidator(DefaultOptions())

	// Test secure result
	result := &ValidationResult{
		HasDNSSEC:  true,
		Algorithms: []Algorithm{AlgECDSAP256},
		Issues:     nil,
	}
	v.calculateScore(result)

	if result.Score < 90 {
		t.Errorf("Score = %d, want >= 90 for secure config", result.Score)
	}
	if result.Grade != "A+" && result.Grade != "A" {
		t.Errorf("Grade = %s, want A+ or A", result.Grade)
	}

	// Test no DNSSEC
	result2 := &ValidationResult{HasDNSSEC: false}
	v.calculateScore(result2)

	if result2.Score != 0 {
		t.Errorf("Score = %d, want 0 for no DNSSEC", result2.Score)
	}
}

func TestGetIssuesBySeverity(t *testing.T) {
	result := &ValidationResult{
		Issues: []Issue{
			{Severity: "low", Title: "Low Issue"},
			{Severity: "critical", Title: "Critical Issue"},
			{Severity: "medium", Title: "Medium Issue"},
		},
	}

	sorted := result.GetIssuesBySeverity()

	if sorted[0].Severity != "critical" {
		t.Error("critical should be first")
	}
	if sorted[len(sorted)-1].Severity != "low" {
		t.Error("low should be last")
	}
}

func TestFormat(t *testing.T) {
	result := &ValidationResult{
		Domain:    "example.com",
		Status:    StatusSecure,
		Grade:     "A",
		Score:     95,
		HasDNSSEC: true,
		KeyCount:  4,
		TotalTime: 100 * time.Millisecond,
	}

	output := result.Format()

	if len(output) == 0 {
		t.Error("Format returned empty string")
	}
	if !containsStr(output, "example.com") {
		t.Error("should contain domain")
	}
	if !containsStr(output, "A") {
		t.Error("should contain grade")
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDetermineStatus(t *testing.T) {
	v := NewValidator(DefaultOptions())

	// Test all secure
	result := &ValidationResult{
		Chain: []ChainLink{
			{Zone: ".", Status: StatusSecure, DNSKEYs: []DNSKEYRecord{{}}},
			{Zone: "com", Status: StatusSecure, DNSKEYs: []DNSKEYRecord{{}}},
		},
	}
	v.determineStatus(result)

	if result.Status != StatusSecure {
		t.Errorf("Status = %v, want secure", result.Status)
	}

	// Test with bogus
	result2 := &ValidationResult{
		Chain: []ChainLink{
			{Zone: ".", Status: StatusSecure},
			{Zone: "com", Status: StatusBogus},
		},
	}
	v.determineStatus(result2)

	if result2.Status != StatusBogus {
		t.Errorf("Status = %v, want bogus", result2.Status)
	}
}

func TestFindIssues(t *testing.T) {
	v := NewValidator(DefaultOptions())

	// Test weak algorithm detection
	result := &ValidationResult{
		HasDNSSEC:  true,
		Algorithms: []Algorithm{AlgRSAMD5},
	}
	v.findIssues(result)

	found := false
	for _, issue := range result.Issues {
		if issue.Severity == "critical" {
			found = true
			break
		}
	}
	if !found {
		t.Error("should detect critical issue for RSA/MD5")
	}
}
