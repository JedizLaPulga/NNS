package cidrmerge

import (
	"net"
	"strings"
	"testing"
)

func TestMergeSimple(t *testing.T) {
	result := Merge([]string{"10.0.0.0/24", "10.0.1.0/24"})
	if result.OutputCount != 1 {
		t.Fatalf("expected 1 merged CIDR, got %d: %v", result.OutputCount, result.Output)
	}
	if result.Output[0] != "10.0.0.0/23" {
		t.Errorf("expected 10.0.0.0/23, got %s", result.Output[0])
	}
}

func TestMergeDuplicates(t *testing.T) {
	result := Merge([]string{"10.0.0.0/24", "10.0.0.0/24", "10.0.0.0/24"})
	if result.OutputCount != 1 {
		t.Errorf("expected 1 output for duplicates, got %d", result.OutputCount)
	}
}

func TestMergeContained(t *testing.T) {
	result := Merge([]string{"10.0.0.0/16", "10.0.1.0/24", "10.0.2.0/24"})
	if result.OutputCount != 1 {
		t.Fatalf("expected 1 output for contained CIDRs, got %d: %v", result.OutputCount, result.Output)
	}
	if result.Output[0] != "10.0.0.0/16" {
		t.Errorf("expected 10.0.0.0/16, got %s", result.Output[0])
	}
}

func TestMergeNoOverlap(t *testing.T) {
	result := Merge([]string{"10.0.0.0/24", "192.168.1.0/24"})
	if result.OutputCount != 2 {
		t.Errorf("expected 2 non-overlapping CIDRs, got %d", result.OutputCount)
	}
}

func TestMergeEmpty(t *testing.T) {
	result := Merge([]string{})
	if result.OutputCount != 0 {
		t.Errorf("expected 0 for empty input, got %d", result.OutputCount)
	}
}

func TestMergeInvalid(t *testing.T) {
	result := Merge([]string{"not-a-cidr", "10.0.0.0/24"})
	if len(result.Invalid) != 1 {
		t.Errorf("expected 1 invalid, got %d", len(result.Invalid))
	}
	if result.OutputCount != 1 {
		t.Errorf("expected 1 valid output, got %d", result.OutputCount)
	}
}

func TestMergeBareIP(t *testing.T) {
	result := Merge([]string{"10.0.0.1"})
	if result.OutputCount != 1 {
		t.Fatalf("expected 1 output for bare IP, got %d", result.OutputCount)
	}
	if result.Output[0] != "10.0.0.1/32" {
		t.Errorf("expected 10.0.0.1/32, got %s", result.Output[0])
	}
}

func TestMergeFourToTwo(t *testing.T) {
	result := Merge([]string{
		"10.0.0.0/24",
		"10.0.1.0/24",
		"10.0.2.0/24",
		"10.0.3.0/24",
	})
	if result.OutputCount != 1 {
		t.Errorf("expected 1 merged CIDR (/22), got %d: %v", result.OutputCount, result.Output)
	}
}

func TestContains(t *testing.T) {
	ok, err := Contains("10.0.0.0/24", "10.0.0.50")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("10.0.0.50 should be contained in 10.0.0.0/24")
	}

	ok, err = Contains("10.0.0.0/24", "10.0.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("10.0.1.1 should NOT be contained in 10.0.0.0/24")
	}
}

func TestContainsInvalidCIDR(t *testing.T) {
	_, err := Contains("invalid", "10.0.0.1")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestContainsInvalidIP(t *testing.T) {
	_, err := Contains("10.0.0.0/24", "invalid")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestOverlaps(t *testing.T) {
	ok, err := Overlaps("10.0.0.0/24", "10.0.0.128/25")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected overlap between 10.0.0.0/24 and 10.0.0.128/25")
	}

	ok, err = Overlaps("10.0.0.0/24", "10.0.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("10.0.0.0/24 and 10.0.1.0/24 should NOT overlap")
	}
}

func TestOverlapsInvalid(t *testing.T) {
	_, err := Overlaps("invalid", "10.0.0.0/24")
	if err == nil {
		t.Error("expected error for invalid first CIDR")
	}
	_, err = Overlaps("10.0.0.0/24", "invalid")
	if err == nil {
		t.Error("expected error for invalid second CIDR")
	}
}

func TestExclude(t *testing.T) {
	remaining, err := Exclude("10.0.0.0/24", "10.0.0.0/25")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining CIDR, got %d: %v", len(remaining), remaining)
	}
	if remaining[0] != "10.0.0.128/25" {
		t.Errorf("expected 10.0.0.128/25, got %s", remaining[0])
	}
}

func TestExcludeNonOverlapping(t *testing.T) {
	remaining, err := Exclude("10.0.0.0/24", "192.168.0.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining (whole base), got %d", len(remaining))
	}
	if remaining[0] != "10.0.0.0/24" {
		t.Errorf("expected 10.0.0.0/24, got %s", remaining[0])
	}
}

func TestExcludeInvalidBase(t *testing.T) {
	_, err := Exclude("invalid", "10.0.0.0/24")
	if err == nil {
		t.Error("expected error for invalid base")
	}
}

func TestExcludeInvalidExclude(t *testing.T) {
	_, err := Exclude("10.0.0.0/24", "invalid")
	if err == nil {
		t.Error("expected error for invalid exclude")
	}
}

func TestHostCount(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		{"10.0.0.0/24", "254"},   // 256 - 2
		{"10.0.0.0/32", "1"},     // single host
		{"10.0.0.0/31", "2"},     // point-to-point
		{"10.0.0.0/16", "65534"}, // 65536 - 2
		{"10.0.0.0/8", "16777214"},
	}

	for _, tt := range tests {
		count, err := HostCount(tt.cidr)
		if err != nil {
			t.Fatalf("HostCount(%s): %v", tt.cidr, err)
		}
		if count.String() != tt.want {
			t.Errorf("HostCount(%s) = %s, want %s", tt.cidr, count.String(), tt.want)
		}
	}
}

func TestHostCountInvalid(t *testing.T) {
	_, err := HostCount("invalid")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestFormatResultOutput(t *testing.T) {
	r := Merge([]string{"10.0.0.0/24", "10.0.1.0/24"})
	output := FormatResult(r)

	checks := []string{
		"Input CIDRs",
		"Output CIDRs",
		"Reduced",
		"10.0.0.0/23",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("format output should contain %q", check)
		}
	}
}

func TestFormatResultWithInvalid(t *testing.T) {
	r := Merge([]string{"not-valid", "10.0.0.0/24"})
	output := FormatResult(r)
	if !strings.Contains(output, "not-valid") {
		t.Error("should show invalid entries")
	}
}

func TestMergeReduced(t *testing.T) {
	result := Merge([]string{"10.0.0.0/24", "10.0.1.0/24"})
	if result.Reduced != 1 {
		t.Errorf("expected reduced=1, got %d", result.Reduced)
	}
}

func TestCompareIP(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"10.0.0.0", "10.0.0.1", -1},
		{"10.0.0.1", "10.0.0.0", 1},
		{"10.0.0.0", "10.0.0.0", 0},
	}
	for _, tt := range tests {
		got := compareIP(net.ParseIP(tt.a), net.ParseIP(tt.b))
		if got != tt.want {
			t.Errorf("compareIP(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
