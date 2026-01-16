package ipinfo

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := isPrivateIP(ip)
		if got != tt.want {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsBogonIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"0.0.0.0", true},
		{"0.1.2.3", true},
		{"169.254.1.1", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := isBogonIP(ip)
		if got != tt.want {
			t.Errorf("isBogonIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestCountryFlag(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"US", "🇺🇸"},
		{"GB", "🇬🇧"},
		{"DE", "🇩🇪"},
		{"JP", "🇯🇵"},
		{"", ""},
		{"USA", ""},
	}

	for _, tt := range tests {
		got := CountryFlag(tt.code)
		if got != tt.want {
			t.Errorf("CountryFlag(%q) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client.Timeout == 0 {
		t.Error("Client timeout should not be 0")
	}
	if client.HTTPClient == nil {
		t.Error("Client HTTPClient should not be nil")
	}
}

func TestLookupPrivateIP(t *testing.T) {
	client := NewClient()
	info, err := client.Lookup(nil, "192.168.1.1")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !info.IsPrivate {
		t.Error("192.168.1.1 should be marked as private")
	}
	if info.Org != "Private Network" {
		t.Errorf("Org = %q, want 'Private Network'", info.Org)
	}
}

func TestLookupBogonIP(t *testing.T) {
	client := NewClient()
	info, err := client.Lookup(nil, "0.0.0.1")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !info.IsBogon {
		t.Error("0.0.0.1 should be marked as bogon")
	}
}

func TestLookupInvalidIP(t *testing.T) {
	client := NewClient()
	_, err := client.Lookup(nil, "invalid")
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
}
