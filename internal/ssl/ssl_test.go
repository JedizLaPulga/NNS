package ssl

import (
	"testing"
)

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
	}{
		{"google.com", "google.com", 443},
		{"google.com:443", "google.com", 443},
		{"example.com:8443", "example.com", 8443},
		{"localhost:4433", "localhost", 4433},
		{"192.168.1.1", "192.168.1.1", 443},
		{"192.168.1.1:8080", "192.168.1.1", 8080},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := ParseHostPort(tt.input)
			if host != tt.wantHost {
				t.Errorf("ParseHostPort(%q) host = %q, want %q", tt.input, host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("ParseHostPort(%q) port = %d, want %d", tt.input, port, tt.wantPort)
			}
		})
	}
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A+"},
		{95, "A+"},
		{90, "A"},
		{85, "B"},
		{75, "C"},
		{65, "D"},
		{50, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := scoreToGrade(tt.score)
			if got != tt.want {
				t.Errorf("scoreToGrade(%d) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestNewAnalyzer(t *testing.T) {
	a := NewAnalyzer()

	if a.Timeout == 0 {
		t.Error("NewAnalyzer().Timeout should not be zero")
	}

	if !a.InsecureSkipVerify {
		t.Error("NewAnalyzer().InsecureSkipVerify should be true")
	}
}

func TestAnalyzeGoogle(t *testing.T) {
	a := NewAnalyzer()
	result := a.Analyze("google.com", 443)

	if result.Error != nil {
		t.Skipf("Network issue: %v", result.Error)
	}

	// Certificate should have valid dates
	if result.Certificate.Subject == "" {
		t.Error("Certificate subject should not be empty")
	}

	if result.Certificate.DaysRemaining < 0 {
		t.Error("Google cert should not be expired")
	}

	// Should have SANs
	if len(result.Certificate.SANs) == 0 {
		t.Error("Google cert should have SANs")
	}

	// Should have good grade
	if result.Security.Grade == "F" {
		t.Errorf("Google should not have F grade, issues: %v", result.Security.Issues)
	}

	// Should be TLS 1.2+
	if result.Security.TLSVersion == "" {
		t.Error("TLS version should be set")
	}
}

func TestAnalyzeInvalidHost(t *testing.T) {
	a := NewAnalyzer()
	result := a.Analyze("this-host-does-not-exist-12345.invalid", 443)

	if result.Error == nil {
		t.Error("Should error on invalid host")
	}
}

func TestResultToJSON(t *testing.T) {
	a := NewAnalyzer()
	result := a.Analyze("google.com", 443)

	if result.Error != nil {
		t.Skipf("Network issue: %v", result.Error)
	}

	json, err := result.ToJSON()
	if err != nil {
		t.Errorf("ToJSON() error: %v", err)
	}

	if json == "" {
		t.Error("ToJSON() should not be empty")
	}

	// Should contain key fields
	if !contains(json, "subject") || !contains(json, "grade") {
		t.Error("JSON should contain subject and grade")
	}
}

func TestExpiryStatus(t *testing.T) {
	a := NewAnalyzer()
	result := a.Analyze("google.com", 443)

	if result.Error != nil {
		t.Skipf("Network issue: %v", result.Error)
	}

	status := result.ExpiryStatus()
	if status == "" {
		t.Error("ExpiryStatus() should not be empty")
	}

	// Google should be GOOD or OK
	if !contains(status, "GOOD") && !contains(status, "OK") && !contains(status, "WARNING") {
		t.Logf("Unexpected expiry status: %s", status)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func BenchmarkAnalyze(b *testing.B) {
	a := NewAnalyzer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Analyze("google.com", 443)
	}
}
