package dnsenum

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDefaultWordlist(t *testing.T) {
	wl := DefaultWordlist()
	if len(wl) == 0 {
		t.Error("wordlist should not be empty")
	}

	seen := make(map[string]bool)
	for _, w := range wl {
		if w == "" {
			t.Error("wordlist should not contain empty strings")
		}
		if seen[w] {
			t.Errorf("duplicate word: %s", w)
		}
		seen[w] = true
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions("example.com")
	if opts.Domain != "example.com" {
		t.Errorf("unexpected domain: %s", opts.Domain)
	}
	if opts.Concurrency != 10 {
		t.Errorf("unexpected concurrency: %d", opts.Concurrency)
	}
	if opts.Timeout != 3*time.Second {
		t.Errorf("unexpected timeout: %s", opts.Timeout)
	}
	if !opts.TryZoneXfer {
		t.Error("TryZoneXfer should be true by default")
	}
	if len(opts.Wordlist) == 0 {
		t.Error("should have default wordlist")
	}
}

func TestEnumerateBasic(t *testing.T) {
	opts := DefaultOptions("example.com")
	opts.Wordlist = []string{"www"}
	opts.TryZoneXfer = false
	opts.Timeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := Enumerate(ctx, opts)
	if s.Domain != "example.com" {
		t.Errorf("unexpected domain: %s", s.Domain)
	}
	if s.TotalChecked != 1 {
		t.Errorf("expected 1 checked, got %d", s.TotalChecked)
	}
	if s.Duration <= 0 {
		t.Error("duration should be positive")
	}
}

func TestEnumerateContextCancel(t *testing.T) {
	opts := DefaultOptions("example.com")
	opts.Wordlist = DefaultWordlist()
	opts.TryZoneXfer = false

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := Enumerate(ctx, opts)
	// Should still return a valid summary
	if s.Domain != "example.com" {
		t.Errorf("unexpected domain: %s", s.Domain)
	}
}

func TestEnumerateEmptyWordlist(t *testing.T) {
	opts := DefaultOptions("example.com")
	opts.Wordlist = []string{}
	opts.TryZoneXfer = false

	s := Enumerate(context.Background(), opts)
	if s.TotalFound != 0 {
		t.Errorf("expected 0 found with empty wordlist, got %d", s.TotalFound)
	}
	if s.TotalChecked != 0 {
		t.Errorf("expected 0 checked, got %d", s.TotalChecked)
	}
}

func TestFormatSummaryEmpty(t *testing.T) {
	s := Summary{
		Domain:       "test.com",
		TotalChecked: 50,
		TotalFound:   0,
		Duration:     100 * time.Millisecond,
	}

	out := FormatSummary(s)
	if !strings.Contains(out, "test.com") {
		t.Error("expected domain in output")
	}
	if !strings.Contains(out, "50") {
		t.Error("expected checked count")
	}
}

func TestFormatSummaryWithResults(t *testing.T) {
	s := Summary{
		Domain:       "example.com",
		TotalChecked: 10,
		TotalFound:   2,
		Duration:     500 * time.Millisecond,
		Nameservers:  []string{"ns1.example.com", "ns2.example.com"},
		Subdomains: []SubdomainResult{
			{Subdomain: "www", FQDN: "www.example.com", IPs: []string{"93.184.216.34"}, Source: "wordlist"},
			{Subdomain: "mail", FQDN: "mail.example.com", IPs: []string{"93.184.216.35"}, CNAMEs: []string{"mx.example.com"}, Source: "wordlist"},
		},
		ZoneTransfers: []ZoneTransferResult{
			{Server: "ns1.example.com", Success: false, Error: "refused"},
		},
	}

	out := FormatSummary(s)
	if !strings.Contains(out, "www.example.com") {
		t.Error("expected www subdomain")
	}
	if !strings.Contains(out, "mail.example.com") {
		t.Error("expected mail subdomain")
	}
	if !strings.Contains(out, "ns1.example.com") {
		t.Error("expected nameserver")
	}
	if !strings.Contains(out, "Zone Transfer") {
		t.Error("expected zone transfer section")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("should not truncate short strings")
	}
	result := truncate("a very long string here", 10)
	if result == "a very long string here" {
		t.Error("should have truncated")
	}
	if !strings.HasSuffix(result, "…") {
		t.Error("should end with ellipsis")
	}
}

func TestMaxInt(t *testing.T) {
	if maxInt(1, 2) != 2 {
		t.Error("maxInt(1,2) should be 2")
	}
	if maxInt(5, 3) != 5 {
		t.Error("maxInt(5,3) should be 5")
	}
}

func TestBuildResolverDefault(t *testing.T) {
	r := buildResolver("", 3*time.Second)
	if r == nil {
		t.Error("resolver should not be nil")
	}
}

func TestBuildResolverCustom(t *testing.T) {
	r := buildResolver("8.8.8.8", 3*time.Second)
	if r == nil {
		t.Error("resolver should not be nil")
	}
	if !r.PreferGo {
		t.Error("custom resolver should prefer Go")
	}
}

func TestBuildResolverWithPort(t *testing.T) {
	r := buildResolver("8.8.8.8:53", 3*time.Second)
	if r == nil {
		t.Error("resolver should not be nil")
	}
}

func TestLookupReverseDNS(t *testing.T) {
	// Use loopback — should generally resolve
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := LookupReverseDNS(ctx, []string{"127.0.0.1"}, 3*time.Second)
	// May or may not resolve depending on system config — just ensure no panic
	_ = results
}

func TestSubdomainResultFields(t *testing.T) {
	r := SubdomainResult{
		Subdomain: "api",
		FQDN:      "api.example.com",
		IPs:       []string{"1.2.3.4"},
		CNAMEs:    []string{"lb.example.com"},
		Source:    "wordlist",
	}

	if r.Subdomain != "api" {
		t.Error("unexpected subdomain")
	}
	if r.FQDN != "api.example.com" {
		t.Error("unexpected fqdn")
	}
	if len(r.IPs) != 1 {
		t.Error("expected 1 IP")
	}
	if len(r.CNAMEs) != 1 {
		t.Error("expected 1 CNAME")
	}
}

func TestZoneTransferResultFields(t *testing.T) {
	zr := ZoneTransferResult{
		Server:  "ns1.example.com",
		Success: false,
		Error:   "refused",
	}
	if zr.Success {
		t.Error("should not be successful")
	}
	if zr.Server != "ns1.example.com" {
		t.Error("unexpected server")
	}
}
