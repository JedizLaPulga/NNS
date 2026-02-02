package blacklist

import (
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", opts.Timeout)
	}
	if opts.Concurrency != 10 {
		t.Errorf("Concurrency = %d, want 10", opts.Concurrency)
	}
	if !opts.IncludeTXT {
		t.Error("IncludeTXT should be true")
	}
	if len(opts.Blacklists) == 0 {
		t.Error("Blacklists should not be empty")
	}
}

func TestNewChecker(t *testing.T) {
	c := NewChecker(DefaultOptions())
	if c == nil {
		t.Fatal("NewChecker returned nil")
	}
	if c.resolver == nil {
		t.Error("resolver not initialized")
	}
}

func TestCommonBlacklists(t *testing.T) {
	if len(CommonBlacklists) < 10 {
		t.Errorf("expected at least 10 blacklists, got %d", len(CommonBlacklists))
	}

	// Check all have required fields
	for _, bl := range CommonBlacklists {
		if bl.Name == "" {
			t.Error("blacklist Name should not be empty")
		}
		if bl.Zone == "" {
			t.Error("blacklist Zone should not be empty")
		}
		if bl.Type == "" {
			t.Error("blacklist Type should not be empty")
		}
	}
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"192.168.1.1", "1.1.168.192", false},
		{"8.8.8.8", "8.8.8.8", false},
		{"10.0.0.1", "1.0.0.10", false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ReverseIP(tt.input)
			if tt.hasError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("got %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestListType(t *testing.T) {
	tests := []ListType{TypeDNSBL, TypeURIBL, TypeSURBL}
	for _, lt := range tests {
		if lt == "" {
			t.Error("ListType should not be empty")
		}
	}
}

func TestCheckResultIsClean(t *testing.T) {
	clean := &CheckResult{TotalListed: 0}
	if !clean.IsClean() {
		t.Error("should be clean")
	}

	dirty := &CheckResult{TotalListed: 1}
	if dirty.IsClean() {
		t.Error("should not be clean")
	}
}

func TestCalculateScore(t *testing.T) {
	c := NewChecker(DefaultOptions())

	// Clean result
	clean := &CheckResult{TotalChecks: 10, TotalListed: 0}
	c.calculateScore(clean)
	if clean.Score != 100 {
		t.Errorf("Score = %d, want 100 for clean", clean.Score)
	}
	if clean.Risk != "low" {
		t.Errorf("Risk = %s, want low", clean.Risk)
	}

	// Some listings
	some := &CheckResult{TotalChecks: 10, TotalListed: 3}
	c.calculateScore(some)
	if some.Risk != "high" {
		t.Errorf("Risk = %s, want high for 3 listings", some.Risk)
	}

	// Many listings
	many := &CheckResult{TotalChecks: 10, TotalListed: 8}
	c.calculateScore(many)
	if many.Risk != "critical" {
		t.Errorf("Risk = %s, want critical for 8 listings", many.Risk)
	}
}

func TestGetListedBlacklists(t *testing.T) {
	result := &CheckResult{
		Listings: []ListingResult{
			{Blacklist: Blacklist{Name: "List1"}, Listed: true},
			{Blacklist: Blacklist{Name: "List2"}, Listed: false},
			{Blacklist: Blacklist{Name: "List3"}, Listed: true},
		},
	}

	listed := result.GetListedBlacklists()
	if len(listed) != 2 {
		t.Errorf("got %d listed, want 2", len(listed))
	}
}

func TestFormat(t *testing.T) {
	result := &CheckResult{
		Target:      "192.168.1.1",
		TargetType:  "ip",
		TotalChecks: 10,
		TotalListed: 2,
		Score:       80,
		Risk:        "medium",
		Duration:    100 * time.Millisecond,
		Categories:  map[string]int{"spam": 2},
	}

	output := result.Format()
	if len(output) == 0 {
		t.Error("Format returned empty string")
	}
	if !containsStr(output, "192.168.1.1") {
		t.Error("should contain target")
	}
	if !containsStr(output, "80/100") {
		t.Error("should contain score")
	}
}

func TestFormatCompact(t *testing.T) {
	result := &CheckResult{
		Target:      "8.8.8.8",
		TotalChecks: 10,
		TotalListed: 0,
		Score:       100,
		Risk:        "low",
	}

	compact := result.FormatCompact()
	if !containsStr(compact, "8.8.8.8") {
		t.Error("should contain target")
	}
	if !containsStr(compact, "0/10") {
		t.Error("should contain listing count")
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

func TestBlacklistCategories(t *testing.T) {
	categories := make(map[string]int)
	for _, bl := range CommonBlacklists {
		categories[bl.Category]++
	}

	if categories["spam"] == 0 {
		t.Error("should have spam category blacklists")
	}
}
