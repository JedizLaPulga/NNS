package tlsaudit

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	a := New(DefaultConfig())
	if a == nil {
		t.Error("New() returned nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
	}
}

func TestSeverity_String(t *testing.T) {
	if Info.String() != "INFO" {
		t.Errorf("got %q", Info.String())
	}
	if Critical.String() != "CRITICAL" {
		t.Errorf("got %q", Critical.String())
	}
}

func TestSeverity_Icon(t *testing.T) {
	if Info.Icon() != "ℹ️" {
		t.Errorf("got %q", Info.Icon())
	}
	if Critical.Icon() != "🔴" {
		t.Errorf("got %q", Critical.Icon())
	}
}

func TestScoreToGrade(t *testing.T) {
	if scoreToGrade(100) != "A+" {
		t.Error("expected A+")
	}
	if scoreToGrade(50) != "F" {
		t.Error("expected F")
	}
}

func TestParseHostPort(t *testing.T) {
	host, port := ParseHostPort("example.com")
	if host != "example.com" || port != 443 {
		t.Errorf("got %s:%d", host, port)
	}
	host, port = ParseHostPort("example.com:8443")
	if host != "example.com" || port != 8443 {
		t.Errorf("got %s:%d", host, port)
	}
}

func TestFormatIssue(t *testing.T) {
	issue := Issue{Severity: High, Title: "Test", Description: "Desc"}
	if FormatIssue(issue) == "" {
		t.Error("empty output")
	}
}

func TestFormatVuln(t *testing.T) {
	v := VulnerabilityCheck{Name: "BEAST", Tested: true, Vulnerable: true}
	if FormatVuln(v) == "" {
		t.Error("empty output")
	}
}

func TestCountBySeverity(t *testing.T) {
	issues := []Issue{{Severity: High}, {Severity: High}, {Severity: Low}}
	counts := CountBySeverity(issues)
	if counts[High] != 2 {
		t.Errorf("High = %d", counts[High])
	}
}

func TestGradeColor(t *testing.T) {
	if GradeColor("A+") == "" {
		t.Error("empty color")
	}
}

func TestAuditor_InvalidHost(t *testing.T) {
	cfg := Config{Timeout: 100 * time.Millisecond, CheckProtocols: false}
	a := New(cfg)
	result := a.Audit("invalid.nowhere", 443)
	if result.Connected {
		t.Error("should not connect")
	}
	if result.Grade != "F" {
		t.Errorf("Grade = %q", result.Grade)
	}
}
