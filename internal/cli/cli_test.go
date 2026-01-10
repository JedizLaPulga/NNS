package cli

import (
	"testing"
)

func TestFormatTable(t *testing.T) {
	headers := []string{"Name", "Value", "Status"}
	rows := [][]string{
		{"Item1", "100", "OK"},
		{"Item2", "200", "OK"},
	}

	result := FormatTable(headers, rows)

	// Check headers are present
	if !contains(result, "Name") {
		t.Error("Table should contain 'Name' header")
	}
	if !contains(result, "Value") {
		t.Error("Table should contain 'Value' header")
	}

	// Check data is present
	if !contains(result, "Item1") {
		t.Error("Table should contain 'Item1'")
	}
	if !contains(result, "100") {
		t.Error("Table should contain '100'")
	}

	// Check separator
	if !contains(result, "---") {
		t.Error("Table should contain separator")
	}
}

func TestFormatTableEmpty(t *testing.T) {
	headers := []string{"A", "B"}
	rows := [][]string{}

	result := FormatTable(headers, rows)

	// Should have headers but no data rows
	if !contains(result, "A") {
		t.Error("Table should contain headers even with empty rows")
	}
}

func TestExitCodes(t *testing.T) {
	if ExitSuccess != 0 {
		t.Errorf("ExitSuccess should be 0, got %d", ExitSuccess)
	}
	if ExitError != 1 {
		t.Errorf("ExitError should be 1, got %d", ExitError)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
