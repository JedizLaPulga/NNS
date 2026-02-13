package asn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", opts.Timeout)
	}
	if !opts.FetchRDAP {
		t.Error("expected FetchRDAP=true by default")
	}
}

func TestExpandIPv6(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantLen int
	}{
		{"loopback", "::1", 63}, // 32 nibbles + 31 dots
		{"google dns", "2001:4860:4860::8888", 63},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %s", tt.ip)
			}
			result := expandIPv6(ip)
			if len(result) != tt.wantLen {
				t.Errorf("expandIPv6(%s) length = %d, want %d", tt.ip, len(result), tt.wantLen)
			}
			// Should contain only hex nibbles and dots
			for _, c := range result {
				if c != '.' && !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("unexpected character %c in expanded IPv6", c)
				}
			}
		})
	}
}

func TestExpandIPv6Nil(t *testing.T) {
	result := expandIPv6(nil)
	if result != "" {
		t.Errorf("expected empty string for nil IP, got %q", result)
	}
}

func TestFormatResult(t *testing.T) {
	info := &ASInfo{
		IP:         "8.8.8.8",
		ASN:        15169,
		ASNString:  "AS15169",
		Name:       "GOOGLE, US",
		Prefix:     "8.8.8.0/24",
		Country:    "US",
		Registry:   "arin",
		Allocated:  "2023-12-28",
		LookupTime: 150 * time.Millisecond,
	}

	output := FormatResult(info)

	checks := []string{
		"8.8.8.8",
		"AS15169",
		"GOOGLE",
		"8.8.8.0/24",
		"US",
		"arin",
		"150ms",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("format output should contain %q", check)
		}
	}
}

func TestFormatResultWithPrefixes(t *testing.T) {
	info := &ASInfo{
		IP:         "8.8.8.8",
		ASN:        15169,
		ASNString:  "AS15169",
		Name:       "GOOGLE",
		Prefix:     "8.8.8.0/24",
		Country:    "US",
		Registry:   "arin",
		Allocated:  "2023-12-28",
		Prefixes:   []string{"8.8.8.0/24", "8.8.4.0/24", "8.34.208.0/20"},
		LookupTime: 100 * time.Millisecond,
	}

	output := FormatResult(info)
	if !strings.Contains(output, "3 announced") {
		t.Error("format output should contain prefix count")
	}
}

func TestFormatResultWithPeers(t *testing.T) {
	info := &ASInfo{
		IP:         "8.8.8.8",
		ASN:        15169,
		ASNString:  "AS15169",
		Name:       "GOOGLE",
		Prefix:     "8.8.8.0/24",
		Country:    "US",
		Registry:   "arin",
		Allocated:  "2023-12-28",
		Peers:      []int{3356, 6453, 2914},
		LookupTime: 100 * time.Millisecond,
	}

	output := FormatResult(info)
	if !strings.Contains(output, "3 upstream") {
		t.Error("format output should contain peer count")
	}
}

func TestFormatResultWithDescription(t *testing.T) {
	info := &ASInfo{
		IP:          "8.8.8.8",
		ASN:         15169,
		ASNString:   "AS15169",
		Name:        "GOOGLE",
		Description: "Google LLC",
		Prefix:      "8.8.8.0/24",
		Country:     "US",
		Registry:    "arin",
		Allocated:   "2023-12-28",
		LookupTime:  100 * time.Millisecond,
	}

	output := FormatResult(info)
	if !strings.Contains(output, "Google LLC") {
		t.Error("format output should contain org description")
	}
}

func TestFormatResultManyPrefixes(t *testing.T) {
	prefixes := make([]string, 15)
	for i := range prefixes {
		prefixes[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}

	info := &ASInfo{
		IP:         "10.0.0.1",
		ASN:        64512,
		ASNString:  "AS64512",
		Name:       "TESTNET",
		Prefix:     "10.0.0.0/8",
		Country:    "US",
		Registry:   "arin",
		Allocated:  "2000-01-01",
		Prefixes:   prefixes,
		LookupTime: 50 * time.Millisecond,
	}

	output := FormatResult(info)
	if !strings.Contains(output, "and 5 more") {
		t.Error("should truncate prefixes list with '... and N more'")
	}
}

func TestLookupBatchEmptyTargets(t *testing.T) {
	results := LookupBatch(context.Background(), []string{}, DefaultOptions())
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty targets, got %d", len(results))
	}
}

func TestLookupBatchInvalidTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	opts := DefaultOptions()
	opts.FetchRDAP = false
	results := LookupBatch(ctx, []string{"invalid...host"}, opts)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !strings.Contains(results[0].Description, "Error") {
		t.Error("expected error in description for invalid target")
	}
}

func TestLookupCymruInvalidIP(t *testing.T) {
	info := &ASInfo{}
	err := lookupCymru(context.Background(), "not-an-ip", info)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestLookupCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := LookupOptions{
		Target:  "8.8.8.8",
		Timeout: 1 * time.Second,
	}

	_, err := Lookup(ctx, opts)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestASInfoFields(t *testing.T) {
	info := &ASInfo{
		IP:         "1.2.3.4",
		ASN:        64512,
		ASNString:  "AS64512",
		Name:       "TEST-AS",
		Country:    "US",
		Registry:   "arin",
		Prefix:     "1.2.3.0/24",
		Allocated:  "2024-01-01",
		LookupTime: 42 * time.Millisecond,
	}

	if info.IP != "1.2.3.4" {
		t.Error("IP field mismatch")
	}
	if info.ASN != 64512 {
		t.Error("ASN field mismatch")
	}
	if info.ASNString != "AS64512" {
		t.Error("ASNString field mismatch")
	}
}
