package headers

import (
	"testing"
)

func TestCalculateGrade(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A+"},
		{90, "A+"},
		{85, "A"},
		{80, "A"},
		{75, "B"},
		{65, "C"},
		{55, "D"},
		{40, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		got := calculateGrade(tt.score)
		if got != tt.want {
			t.Errorf("calculateGrade(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestGetMissingHeaders(t *testing.T) {
	result := &Result{
		Headers: map[string]string{
			"Strict-Transport-Security": "max-age=31536000",
			"X-Content-Type-Options":    "nosniff",
		},
	}

	missing := result.GetMissingHeaders()

	// Should have several missing headers
	if len(missing) < 5 {
		t.Errorf("Expected at least 5 missing headers, got %d", len(missing))
	}

	// CSP should be missing
	found := false
	for _, h := range missing {
		if h == "Content-Security-Policy" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected Content-Security-Policy to be in missing headers")
	}
}

func TestGetPresentHeaders(t *testing.T) {
	result := &Result{
		Headers: map[string]string{
			"Strict-Transport-Security": "max-age=31536000",
			"Content-Security-Policy":   "default-src 'self'",
			"X-Content-Type-Options":    "nosniff",
		},
	}

	present := result.GetPresentHeaders()

	if len(present) != 3 {
		t.Errorf("Expected 3 present headers, got %d", len(present))
	}
}

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()

	if analyzer.Timeout == 0 {
		t.Error("Analyzer timeout should not be 0")
	}
	if analyzer.Client == nil {
		t.Error("Analyzer client should not be nil")
	}
}

func TestAnalyzeHeaders(t *testing.T) {
	analyzer := NewAnalyzer()

	// Test with various header combinations
	result := &Result{
		Headers: map[string]string{},
		Issues:  make([]Issue, 0),
	}

	analyzer.analyzeHeaders(result)

	// Should have issues for missing headers
	if len(result.Issues) == 0 {
		t.Error("Expected issues for missing security headers")
	}

	// Score should be less than 100
	if result.Score >= 100 {
		t.Error("Score should be less than 100 with missing headers")
	}
}

func TestAnalyzeHeadersWithHSTS(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &Result{
		Headers: map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		},
		Issues: make([]Issue, 0),
	}

	analyzer.analyzeHeaders(result)

	// Check that no HSTS issues exist
	for _, issue := range result.Issues {
		if issue.Header == "Strict-Transport-Security" && issue.Severity == SeverityCritical {
			t.Error("Should not have critical HSTS issue when header is present")
		}
	}
}
