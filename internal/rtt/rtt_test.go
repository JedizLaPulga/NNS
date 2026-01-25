package rtt

import (
	"context"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New(DefaultConfig())
	if c == nil {
		t.Error("New() returned nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Count != 5 {
		t.Errorf("Count = %d, want 5", cfg.Count)
	}
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
		{"host:99999", true, "", 0},
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

func TestProtocol_String(t *testing.T) {
	if TCP.String() != "TCP" {
		t.Errorf("TCP.String() = %q, want TCP", TCP.String())
	}
	if UDP.String() != "UDP" {
		t.Errorf("UDP.String() = %q, want UDP", UDP.String())
	}
}

func TestResult_Calculate(t *testing.T) {
	r := Result{
		Measurements: []Measurement{
			{Success: true, RTT: 10 * time.Millisecond},
			{Success: true, RTT: 20 * time.Millisecond},
			{Success: true, RTT: 30 * time.Millisecond},
			{Success: false},
		},
	}
	r.Calculate()

	if r.Successful != 3 {
		t.Errorf("Successful = %d, want 3", r.Successful)
	}
	if r.Failed != 1 {
		t.Errorf("Failed = %d, want 1", r.Failed)
	}
	if r.MinRTT != 10*time.Millisecond {
		t.Errorf("MinRTT = %v, want 10ms", r.MinRTT)
	}
	if r.MaxRTT != 30*time.Millisecond {
		t.Errorf("MaxRTT = %v, want 30ms", r.MaxRTT)
	}
	if r.AvgRTT != 20*time.Millisecond {
		t.Errorf("AvgRTT = %v, want 20ms", r.AvgRTT)
	}
	if r.MedianRTT != 20*time.Millisecond {
		t.Errorf("MedianRTT = %v, want 20ms", r.MedianRTT)
	}
	if r.PacketLoss != 25 {
		t.Errorf("PacketLoss = %.1f%%, want 25%%", r.PacketLoss)
	}
}

func TestResult_Rating(t *testing.T) {
	tests := []struct {
		avgRTT    time.Duration
		success   int
		wantStart string
	}{
		{10 * time.Millisecond, 1, "🟢 Excellent"},
		{40 * time.Millisecond, 1, "🟢 Good"},
		{80 * time.Millisecond, 1, "🟡 Fair"},
		{150 * time.Millisecond, 1, "🟠 Slow"},
		{300 * time.Millisecond, 1, "🔴 Poor"},
		{0, 0, "❌ Unreachable"},
	}
	for _, tt := range tests {
		r := Result{AvgRTT: tt.avgRTT, Successful: tt.success}
		got := r.Rating()
		if len(got) < len(tt.wantStart) || got[:len(tt.wantStart)] != tt.wantStart {
			t.Errorf("Rating() for %v = %q, want prefix %q", tt.avgRTT, got, tt.wantStart)
		}
	}
}

func TestSummarize(t *testing.T) {
	results := []Result{
		{Target: Target{Name: "Fast"}, Successful: 1, AvgRTT: 10 * time.Millisecond},
		{Target: Target{Name: "Slow"}, Successful: 1, AvgRTT: 100 * time.Millisecond},
		{Target: Target{Name: "Dead"}, Successful: 0},
	}
	s := Summarize(results)

	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.Reachable != 2 {
		t.Errorf("Reachable = %d, want 2", s.Reachable)
	}
	if s.Unreachable != 1 {
		t.Errorf("Unreachable = %d, want 1", s.Unreachable)
	}
	if s.FastestHost != "Fast" {
		t.Errorf("FastestHost = %q, want Fast", s.FastestHost)
	}
	if s.SlowestHost != "Slow" {
		t.Errorf("SlowestHost = %q, want Slow", s.SlowestHost)
	}
}

func TestSortByRTT(t *testing.T) {
	results := []Result{
		{Target: Target{Name: "slow"}, Successful: 1, AvgRTT: 100 * time.Millisecond},
		{Target: Target{Name: "fast"}, Successful: 1, AvgRTT: 10 * time.Millisecond},
		{Target: Target{Name: "dead"}, Successful: 0},
	}
	SortByRTT(results)
	if results[0].Target.Name != "fast" {
		t.Errorf("First should be fast, got %s", results[0].Target.Name)
	}
	if results[2].Target.Name != "dead" {
		t.Errorf("Last should be dead, got %s", results[2].Target.Name)
	}
}

func TestCommonTargets(t *testing.T) {
	targets := CommonTargets()
	if len(targets) == 0 {
		t.Error("CommonTargets() returned empty slice")
	}
}

func TestSparkLine(t *testing.T) {
	measurements := []Measurement{
		{Success: true, RTT: 10 * time.Millisecond},
		{Success: true, RTT: 50 * time.Millisecond},
		{Success: false},
		{Success: true, RTT: 30 * time.Millisecond},
	}
	spark := SparkLine(measurements)
	if spark == "" {
		t.Error("SparkLine returned empty")
	}
	// Should contain a failure marker
	if len(spark) < 4 {
		t.Error("SparkLine too short")
	}
}

func TestFormatResult(t *testing.T) {
	r := Result{
		Target:     Target{Name: "Test"},
		Successful: 1,
		AvgRTT:     15 * time.Millisecond,
		MinRTT:     10 * time.Millisecond,
		MaxRTT:     20 * time.Millisecond,
		Jitter:     5 * time.Millisecond,
	}
	formatted := FormatResult(r)
	if formatted == "" {
		t.Error("FormatResult returned empty")
	}
}

func TestFormatSummary(t *testing.T) {
	s := Summary{
		Total:       3,
		Reachable:   2,
		Unreachable: 1,
		FastestHost: "Fast",
		FastestRTT:  10 * time.Millisecond,
		SlowestHost: "Slow",
		SlowestRTT:  100 * time.Millisecond,
		AvgRTT:      55 * time.Millisecond,
	}
	formatted := FormatSummary(s)
	if formatted == "" {
		t.Error("FormatSummary returned empty")
	}
}

func TestComparer_Compare(t *testing.T) {
	cfg := Config{
		Count:       2,
		Timeout:     50 * time.Millisecond,
		Interval:    10 * time.Millisecond,
		Concurrency: 2,
	}
	c := New(cfg)
	targets := []Target{
		{Host: "127.0.0.1", Port: 1}, // Unlikely to connect
	}
	ctx := context.Background()
	results := c.Compare(ctx, targets)
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
}
