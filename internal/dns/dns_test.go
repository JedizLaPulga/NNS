package dns

import (
	"context"
	"testing"
	"time"
)

func TestParseRecordType(t *testing.T) {
	tests := []struct {
		input   string
		want    RecordType
		wantErr bool
	}{
		{"A", TypeA, false},
		{"a", TypeA, false},
		{"AAAA", TypeAAAA, false},
		{"MX", TypeMX, false},
		{"TXT", TypeTXT, false},
		{"NS", TypeNS, false},
		{"CNAME", TypeCNAME, false},
		{"PTR", TypePTR, false},
		{"INVALID", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseRecordType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecordType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseRecordType(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"8.8.8.8", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"2001:4860:4860::8888", true},
		{"google.com", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsIPAddress(tt.input)
			if got != tt.want {
				t.Errorf("IsIPAddress(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewResolver(t *testing.T) {
	r := NewResolver()

	if r.Timeout != 5*time.Second {
		t.Errorf("NewResolver().Timeout = %v, want 5s", r.Timeout)
	}

	if r.Server != "" {
		t.Errorf("NewResolver().Server = %q, want empty", r.Server)
	}
}

func TestResolverSetServer(t *testing.T) {
	r := NewResolver()

	r.SetServer("8.8.8.8")
	if r.Server != "8.8.8.8:53" {
		t.Errorf("SetServer() = %q, want 8.8.8.8:53", r.Server)
	}

	r.SetServer("1.1.1.1:5353")
	if r.Server != "1.1.1.1:5353" {
		t.Errorf("SetServer() with port = %q, want 1.1.1.1:5353", r.Server)
	}
}

func TestAllTypes(t *testing.T) {
	types := AllTypes()

	if len(types) == 0 {
		t.Error("AllTypes() returned empty slice")
	}

	// Should include common types
	found := make(map[RecordType]bool)
	for _, rt := range types {
		found[rt] = true
	}

	expected := []RecordType{TypeA, TypeAAAA, TypeMX, TypeTXT, TypeNS}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("AllTypes() missing %s", e)
		}
	}
}

func TestLookupA(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := r.Lookup(ctx, "google.com", TypeA)

	if result.Error != nil {
		t.Skipf("DNS lookup failed (network issue?): %v", result.Error)
	}

	if len(result.Records) == 0 {
		t.Error("Lookup A for google.com returned no records")
	}

	if result.Type != TypeA {
		t.Errorf("Result.Type = %s, want A", result.Type)
	}

	if result.Duration == 0 {
		t.Error("Result.Duration should not be zero")
	}
}

func TestLookupMX(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := r.Lookup(ctx, "google.com", TypeMX)

	if result.Error != nil {
		t.Skipf("DNS lookup failed (network issue?): %v", result.Error)
	}

	if len(result.Records) == 0 {
		t.Error("Lookup MX for google.com returned no records")
	}

	// MX records should have priority set
	for _, rec := range result.Records {
		if rec.Priority == 0 && rec.Value == "" {
			t.Error("MX record missing priority or value")
		}
	}
}

func TestLookupInvalidDomain(t *testing.T) {
	r := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := r.Lookup(ctx, "this-domain-definitely-does-not-exist-12345.invalid", TypeA)

	if result.Error == nil {
		t.Error("Expected error for invalid domain, got nil")
	}
}

func TestLookupUnsupportedType(t *testing.T) {
	r := NewResolver()
	ctx := context.Background()

	result := r.Lookup(ctx, "google.com", RecordType("INVALID"))

	if result.Error == nil {
		t.Error("Expected error for unsupported record type")
	}
}

func BenchmarkLookupA(b *testing.B) {
	r := NewResolver()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Lookup(ctx, "google.com", TypeA)
	}
}
