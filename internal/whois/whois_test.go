package whois

import (
	"testing"
)

func TestGetWhoisServer(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"google.com", "whois.verisign-grs.com"},
		{"example.org", "whois.pir.org"},
		{"test.io", "whois.nic.io"},
		{"example.de", "whois.denic.de"},
		{"unknown.tld", "whois.iana.org"},
	}

	for _, tt := range tests {
		got := getWhoisServer(tt.domain)
		if got != tt.want {
			t.Errorf("getWhoisServer(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestParseDomainWhois(t *testing.T) {
	raw := `
Domain Name: EXAMPLE.COM
Registrar: Example Registrar Inc.
Registrant Organization: Example Corp
Creation Date: 1995-08-14T04:00:00Z
Expiration Date: 2024-08-13T04:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
`
	result := &Result{
		NameServers: make([]string, 0),
		Status:      make([]string, 0),
	}
	parseDomainWhois(result, raw)

	if result.Registrar != "Example Registrar Inc." {
		t.Errorf("Registrar = %q, want 'Example Registrar Inc.'", result.Registrar)
	}
	if len(result.NameServers) != 2 {
		t.Errorf("NameServers count = %d, want 2", len(result.NameServers))
	}
	if result.CreatedDate == "" {
		t.Error("CreatedDate should not be empty")
	}
}

func TestParseIPWhois(t *testing.T) {
	raw := `
NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOOGLE
OrgName:        Google LLC
Country:        US
RegDate:        2014-03-14
`
	result := &Result{}
	parseIPWhois(result, raw)

	if result.Organization != "Google LLC" {
		t.Errorf("Organization = %q, want 'Google LLC'", result.Organization)
	}
	if result.NetName != "GOOGLE" {
		t.Errorf("NetName = %q, want 'GOOGLE'", result.NetName)
	}
	if result.CIDR != "8.8.8.0/24" {
		t.Errorf("CIDR = %q, want '8.8.8.0/24'", result.CIDR)
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client.Timeout == 0 {
		t.Error("NewClient().Timeout should not be 0")
	}
}

func TestResultDaysUntilExpiry(t *testing.T) {
	r := &Result{ExpiresDate: ""}
	if r.DaysUntilExpiry() != -1 {
		t.Error("Empty ExpiresDate should return -1")
	}
}

func TestResultIsExpired(t *testing.T) {
	r := &Result{ExpiresDate: "2000-01-01"}
	if !r.IsExpired() {
		t.Error("Date 2000-01-01 should be expired")
	}

	r2 := &Result{ExpiresDate: "2099-01-01"}
	if r2.IsExpired() {
		t.Error("Date 2099-01-01 should not be expired")
	}
}
