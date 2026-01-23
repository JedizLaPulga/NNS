package conntest

import (
	"context"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tester := New(DefaultConfig())
	if tester == nil {
		t.Error("New() returned nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", cfg.Timeout)
	}
	if cfg.Concurrency != 10 {
		t.Errorf("Concurrency = %d, want 10", cfg.Concurrency)
	}
}

func TestTarget_String(t *testing.T) {
	t1 := Target{Host: "example.com", Port: 80, Name: "Example"}
	if t1.String() != "Example" {
		t.Errorf("String() = %q, want Example", t1.String())
	}
	t2 := Target{Host: "example.com", Port: 80}
	if t2.String() != "example.com:80" {
		t.Errorf("String() = %q, want example.com:80", t2.String())
	}
}

func TestTarget_Address(t *testing.T) {
	tgt := Target{Host: "example.com", Port: 443}
	if tgt.Address() != "example.com:443" {
		t.Errorf("Address() = %q, want example.com:443", tgt.Address())
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		host    string
		port    int
	}{
		{"example.com:80", false, "example.com", 80},
		{"192.168.1.1:443", false, "192.168.1.1", 443},
		{"invalid", true, "", 0},
		{"host:0", true, "", 0},
	}
	for _, tt := range tests {
		tgt, err := ParseTarget(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTarget(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if !tt.wantErr {
			if tgt.Host != tt.host || tgt.Port != tt.port {
				t.Errorf("ParseTarget(%q) = %s:%d, want %s:%d", tt.input, tgt.Host, tgt.Port, tt.host, tt.port)
			}
		}
	}
}

func TestCommonTargets(t *testing.T) {
	targets := CommonTargets()
	if len(targets) == 0 {
		t.Error("CommonTargets() returned empty slice")
	}
}

func TestSummarize(t *testing.T) {
	results := []Result{
		{Success: true, Latency: 10 * time.Millisecond},
		{Success: true, Latency: 20 * time.Millisecond},
		{Success: false},
	}
	s := Summarize(results)
	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.Successful != 2 {
		t.Errorf("Successful = %d, want 2", s.Successful)
	}
	if s.Failed != 1 {
		t.Errorf("Failed = %d, want 1", s.Failed)
	}
	if s.MinLatency != 10*time.Millisecond {
		t.Errorf("MinLatency = %v, want 10ms", s.MinLatency)
	}
	if s.MaxLatency != 20*time.Millisecond {
		t.Errorf("MaxLatency = %v, want 20ms", s.MaxLatency)
	}
}

func TestSortByLatency(t *testing.T) {
	results := []Result{
		{Target: Target{Name: "slow"}, Success: true, Latency: 100 * time.Millisecond},
		{Target: Target{Name: "fast"}, Success: true, Latency: 10 * time.Millisecond},
		{Target: Target{Name: "fail"}, Success: false},
	}
	SortByLatency(results)
	if results[0].Target.Name != "fast" {
		t.Errorf("First should be fast, got %s", results[0].Target.Name)
	}
	if results[2].Target.Name != "fail" {
		t.Errorf("Last should be fail, got %s", results[2].Target.Name)
	}
}

func TestFormatResult(t *testing.T) {
	r := Result{Target: Target{Name: "Test"}, Success: true, Latency: 15500 * time.Microsecond}
	formatted := FormatResult(r)
	if formatted == "" {
		t.Error("FormatResult returned empty")
	}
}

func TestFormatSummary(t *testing.T) {
	s := Summary{Total: 10, Successful: 8, Failed: 2, MinLatency: 10 * time.Millisecond, MaxLatency: 100 * time.Millisecond}
	formatted := FormatSummary(s)
	if formatted == "" {
		t.Error("FormatSummary returned empty")
	}
}

func TestTester_Test(t *testing.T) {
	cfg := Config{Timeout: 50 * time.Millisecond, Concurrency: 2}
	tester := New(cfg)
	targets := []Target{
		{Host: "127.0.0.1", Port: 1, Protocol: TCP}, // Unlikely to connect
	}
	ctx := context.Background()
	results := tester.Test(ctx, targets)
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
}
