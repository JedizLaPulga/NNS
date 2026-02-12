package certhunt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout != 15*time.Second {
		t.Errorf("expected 15s timeout, got %v", opts.Timeout)
	}
	if !opts.CheckLive {
		t.Error("expected CheckLive to be true")
	}
	if opts.MaxResults != 100 {
		t.Errorf("expected max 100, got %d", opts.MaxResults)
	}
}

func TestNewSearcher(t *testing.T) {
	s := NewSearcher(Options{Domain: "example.com"})
	if s.opts.Timeout != 15*time.Second {
		t.Errorf("expected default timeout 15s, got %v", s.opts.Timeout)
	}
	if s.opts.MaxResults != 100 {
		t.Errorf("expected default max 100, got %d", s.opts.MaxResults)
	}
	if s.client == nil {
		t.Error("expected HTTP client to be initialized")
	}
}

func TestSearchEmptyDomain(t *testing.T) {
	s := NewSearcher(Options{})
	_, err := s.Search(context.Background())
	if err == nil {
		t.Error("expected error for empty domain")
	}
}

func TestParseSANs(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"example.com", 1},
		{"example.com\nwww.example.com", 2},
		{"a.com\nb.com\nc.com\n", 3},
		{"\n\n", 0},
	}

	for _, tt := range tests {
		sans := parseSANs(tt.input)
		if len(sans) != tt.want {
			t.Errorf("parseSANs(%q) = %d SANs, want %d", tt.input, len(sans), tt.want)
		}
	}
}

func TestExtractCN(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"CN=Let's Encrypt Authority X3, O=Let's Encrypt", "Let's Encrypt Authority X3"},
		{"O=DigiCert, CN=DigiCert SHA2", "DigiCert SHA2"},
		{"Just some issuer string", "Just some issuer string"},
		{"", "Unknown"},
	}

	for _, tt := range tests {
		got := extractCN(tt.input)
		if got != tt.want {
			t.Errorf("extractCN(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDeduplicateEntries(t *testing.T) {
	entries := []CertEntry{
		{CommonName: "a.com", SerialHex: "AAA"},
		{CommonName: "a.com", SerialHex: "AAA"},
		{CommonName: "b.com", SerialHex: "BBB"},
		{CommonName: "a.com", SerialHex: "CCC"},
	}

	result := deduplicateEntries(entries)
	if len(result) != 3 {
		t.Errorf("expected 3 unique entries, got %d", len(result))
	}
}

func TestDeduplicateEmpty(t *testing.T) {
	result := deduplicateEntries(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 entries for nil, got %d", len(result))
	}
}

func TestResultFormat(t *testing.T) {
	now := time.Now()
	r := &Result{
		Domain:     "example.com",
		TotalFound: 2,
		Unique:     2,
		Expired:    1,
		Wildcard:   1,
		Duration:   500 * time.Millisecond,
		LiveCert: &LiveCertInfo{
			CommonName: "example.com",
			Issuer:     "Let's Encrypt",
			NotBefore:  now.Add(-90 * 24 * time.Hour),
			NotAfter:   now.Add(90 * 24 * time.Hour),
			DaysLeft:   90,
			SigAlgo:    "SHA256-RSA",
			ChainLen:   3,
			SANs:       []string{"example.com", "www.example.com"},
		},
		Entries: []CertEntry{
			{
				CommonName: "*.example.com",
				Issuer:     "DigiCert",
				NotBefore:  now.Add(-30 * 24 * time.Hour),
				NotAfter:   now.Add(335 * 24 * time.Hour),
				DaysLeft:   335,
				IsWildcard: true,
				Source:     "crt.sh",
				SANs:       []string{"*.example.com", "example.com"},
			},
			{
				CommonName: "old.example.com",
				Issuer:     "Let's Encrypt",
				NotBefore:  now.Add(-400 * 24 * time.Hour),
				NotAfter:   now.Add(-10 * 24 * time.Hour),
				IsExpired:  true,
				Source:     "crt.sh",
			},
		},
	}

	output := r.Format()

	if !strings.Contains(output, "CERTIFICATE TRANSPARENCY") {
		t.Error("should contain header")
	}
	if !strings.Contains(output, "example.com") {
		t.Error("should contain domain")
	}
	if !strings.Contains(output, "Live Certificate") {
		t.Error("should contain live cert section")
	}
	if !strings.Contains(output, "WILDCARD") {
		t.Error("should contain wildcard marker")
	}
	if !strings.Contains(output, "EXPIRED") {
		t.Error("should contain expired marker")
	}
	if !strings.Contains(output, "Let's Encrypt") {
		t.Error("should contain issuer name")
	}
	if !strings.Contains(output, "SHA256-RSA") {
		t.Error("should contain sig algorithm")
	}
}

func TestResultFormatCompact(t *testing.T) {
	r := &Result{
		Domain:     "example.com",
		TotalFound: 5,
		Unique:     3,
		Wildcard:   1,
		Expired:    2,
		Duration:   100 * time.Millisecond,
		LiveCert:   &LiveCertInfo{DaysLeft: 45},
	}

	compact := r.FormatCompact()
	if !strings.Contains(compact, "example.com") {
		t.Error("compact should contain domain")
	}
	if !strings.Contains(compact, "5 certs") {
		t.Error("compact should contain cert count")
	}
	if !strings.Contains(compact, "45d left") {
		t.Error("compact should contain days left")
	}
}

func TestResultFormatCompactNoLive(t *testing.T) {
	r := &Result{
		Domain:   "example.com",
		Duration: 10 * time.Millisecond,
	}

	compact := r.FormatCompact()
	if !strings.Contains(compact, "no live cert") {
		t.Error("should indicate no live cert")
	}
}

func TestResultFormatWithErrors(t *testing.T) {
	r := &Result{
		Domain:   "example.com",
		Duration: 10 * time.Millisecond,
		Errors:   []string{"crt.sh: timeout"},
	}

	output := r.Format()
	if !strings.Contains(output, "crt.sh: timeout") {
		t.Error("should contain error message")
	}
}

func TestResultFormatManySANs(t *testing.T) {
	r := &Result{
		Domain:   "example.com",
		Duration: 10 * time.Millisecond,
		Entries: []CertEntry{
			{
				CommonName: "example.com",
				SANs:       []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com", "g.com"},
				Source:     "crt.sh",
			},
		},
		TotalFound: 1,
		Unique:     1,
	}

	output := r.Format()
	if !strings.Contains(output, "+2 more") {
		t.Error("should truncate SANs with count")
	}
}

// TestSearchCrtShMock tests the crt.sh search against a mock server.
func TestSearchCrtShMock(t *testing.T) {
	now := time.Now()
	mockEntries := []crtShEntry{
		{
			ID:         1,
			CommonName: "example.com",
			IssuerName: "CN=Test CA",
			NameValue:  "example.com\nwww.example.com",
			NotBefore:  now.Add(-30 * 24 * time.Hour).Format("2006-01-02T15:04:05"),
			NotAfter:   now.Add(335 * 24 * time.Hour).Format("2006-01-02T15:04:05"),
			SerialNum:  "ABCD1234",
		},
		{
			ID:         2,
			CommonName: "*.example.com",
			IssuerName: "CN=Wildcard CA",
			NameValue:  "*.example.com",
			NotBefore:  now.Add(-10 * 24 * time.Hour).Format("2006-01-02T15:04:05"),
			NotAfter:   now.Add(355 * 24 * time.Hour).Format("2006-01-02T15:04:05"),
			SerialNum:  "EFGH5678",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockEntries)
	}))
	defer server.Close()

	s := NewSearcher(Options{
		Domain:    "example.com",
		CheckLive: false,
		Timeout:   5 * time.Second,
	})

	// Override the search URL by calling the internal method with the mock
	entries, err := s.searchCrtShWithURL(server.URL)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].CommonName != "example.com" {
		t.Errorf("expected example.com, got %s", entries[0].CommonName)
	}
	if entries[1].IsWildcard != true {
		t.Error("second entry should be wildcard")
	}
	if entries[0].Source != "crt.sh" {
		t.Errorf("expected source crt.sh, got %s", entries[0].Source)
	}
	if len(entries[0].SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(entries[0].SANs))
	}
}

func TestSearchCrtShError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	s := NewSearcher(Options{Domain: "example.com", Timeout: 2 * time.Second})
	_, err := s.searchCrtShWithURL(server.URL)
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestSearchCrtShInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer server.Close()

	s := NewSearcher(Options{Domain: "example.com", Timeout: 2 * time.Second})
	_, err := s.searchCrtShWithURL(server.URL)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestCertEntryFields(t *testing.T) {
	now := time.Now()
	e := CertEntry{
		CommonName: "*.example.com",
		SANs:       []string{"*.example.com", "example.com"},
		Issuer:     "DigiCert",
		NotBefore:  now,
		NotAfter:   now.Add(365 * 24 * time.Hour),
		SerialHex:  "AABBCCDD",
		IsExpired:  false,
		DaysLeft:   365,
		IsWildcard: true,
		Source:     "crt.sh",
	}

	if !e.IsWildcard {
		t.Error("should be wildcard")
	}
	if e.IsExpired {
		t.Error("should not be expired")
	}
	if e.DaysLeft != 365 {
		t.Errorf("expected 365 days left, got %d", e.DaysLeft)
	}
}

func TestLiveCertInfoFields(t *testing.T) {
	info := &LiveCertInfo{
		CommonName: "example.com",
		Issuer:     "DigiCert",
		DaysLeft:   90,
		SigAlgo:    "SHA256-RSA",
		ChainLen:   3,
		Version:    3,
		KeyUsage:   []string{"DigitalSignature", "ServerAuth"},
	}

	if info.DaysLeft != 90 {
		t.Errorf("expected 90 days, got %d", info.DaysLeft)
	}
	if info.ChainLen != 3 {
		t.Errorf("expected chain len 3, got %d", info.ChainLen)
	}
	if len(info.KeyUsage) != 2 {
		t.Errorf("expected 2 key usages, got %d", len(info.KeyUsage))
	}
}
