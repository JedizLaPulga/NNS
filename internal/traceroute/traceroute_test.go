package traceroute

import (
	"testing"
	"time"
)

func TestNewTracer(t *testing.T) {
	cfg := Config{
		Target: "google.com",
	}

	tracer := NewTracer(cfg)

	if tracer == nil {
		t.Fatal("NewTracer should not return nil")
	}

	// Check defaults were applied
	if tracer.cfg.MaxHops != 30 {
		t.Errorf("Default MaxHops = %d, want 30", tracer.cfg.MaxHops)
	}

	if tracer.cfg.Queries != 3 {
		t.Errorf("Default Queries = %d, want 3", tracer.cfg.Queries)
	}

	if tracer.cfg.Timeout != 2*time.Second {
		t.Errorf("Default Timeout = %v, want 2s", tracer.cfg.Timeout)
	}

	if tracer.pid == 0 {
		t.Error("PID should not be zero")
	}

	if tracer.sentTimes == nil {
		t.Error("sentTimes map should be initialized")
	}
}

func TestNewTracerWithCustomConfig(t *testing.T) {
	cfg := Config{
		Target:    "example.com",
		MaxHops:   15,
		Queries:   5,
		Timeout:   5 * time.Second,
		ResolveAS: true,
	}

	tracer := NewTracer(cfg)

	if tracer.cfg.MaxHops != 15 {
		t.Errorf("MaxHops = %d, want 15", tracer.cfg.MaxHops)
	}

	if tracer.cfg.Queries != 5 {
		t.Errorf("Queries = %d, want 5", tracer.cfg.Queries)
	}

	if tracer.cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", tracer.cfg.Timeout)
	}

	if !tracer.cfg.ResolveAS {
		t.Error("ResolveAS should be true")
	}
}

func TestParseIP(t *testing.T) {
	tests := []struct {
		ip   string
		want []string
	}{
		{"8.8.8.8", []string{"8", "8", "8", "8"}},
		{"1.2.3.4", []string{"1", "2", "3", "4"}},
		{"192.168.1.1", []string{"192", "168", "1", "1"}},
		{"invalid", nil},
		{"", nil},
		{"::1", nil}, // IPv6 not supported
	}

	for _, tt := range tests {
		got := parseIP(tt.ip)

		if tt.want == nil {
			if got != nil {
				t.Errorf("parseIP(%q) = %v, want nil", tt.ip, got)
			}
			continue
		}

		if len(got) != len(tt.want) {
			t.Errorf("parseIP(%q) len = %d, want %d", tt.ip, len(got), len(tt.want))
			continue
		}

		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseIP(%q)[%d] = %q, want %q", tt.ip, i, got[i], tt.want[i])
			}
		}
	}
}

func TestHopStruct(t *testing.T) {
	hop := &Hop{
		TTL:         5,
		IP:          "8.8.8.8",
		Hosts:       []string{"dns.google"},
		ASN:         "AS15169",
		Org:         "Google",
		RTTs:        []time.Duration{10 * time.Millisecond, 12 * time.Millisecond},
		ReachedDest: false,
		Timeout:     false,
		ProbesSent:  3,
	}

	if hop.TTL != 5 {
		t.Errorf("TTL = %d, want 5", hop.TTL)
	}

	if hop.IP != "8.8.8.8" {
		t.Errorf("IP = %q, want 8.8.8.8", hop.IP)
	}

	if len(hop.RTTs) != 2 {
		t.Errorf("RTTs count = %d, want 2", len(hop.RTTs))
	}

	if len(hop.Hosts) != 1 || hop.Hosts[0] != "dns.google" {
		t.Errorf("Hosts = %v, want [dns.google]", hop.Hosts)
	}

	if hop.ASN != "AS15169" {
		t.Errorf("ASN = %q, want AS15169", hop.ASN)
	}

	if hop.Org != "Google" {
		t.Errorf("Org = %q, want Google", hop.Org)
	}

	if hop.ReachedDest {
		t.Error("ReachedDest should be false")
	}

	if hop.Timeout {
		t.Error("Timeout should be false")
	}

	if hop.ProbesSent != 3 {
		t.Errorf("ProbesSent = %d, want 3", hop.ProbesSent)
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{
		Target:    "example.com",
		MaxHops:   20,
		Queries:   4,
		Timeout:   3 * time.Second,
		ResolveAS: true,
	}

	if cfg.Target != "example.com" {
		t.Errorf("Target = %q, want example.com", cfg.Target)
	}

	if cfg.MaxHops != 20 {
		t.Errorf("MaxHops = %d, want 20", cfg.MaxHops)
	}

	if cfg.Queries != 4 {
		t.Errorf("Queries = %d, want 4", cfg.Queries)
	}

	if cfg.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want 3s", cfg.Timeout)
	}

	if !cfg.ResolveAS {
		t.Error("ResolveAS should be true")
	}
}

// Note: LookupAS requires network access, so we test it carefully
func TestLookupASInvalid(t *testing.T) {
	asn, org := LookupAS("invalid-not-an-ip")

	if asn != "" || org != "" {
		t.Error("LookupAS should return empty for invalid IP")
	}
}
