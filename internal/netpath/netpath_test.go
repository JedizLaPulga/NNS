package netpath

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.MaxHops != 30 {
		t.Errorf("expected MaxHops 30, got %d", opts.MaxHops)
	}
	if opts.ProbesPerHop != 5 {
		t.Errorf("expected ProbesPerHop 5, got %d", opts.ProbesPerHop)
	}
	if !opts.ResolveHosts {
		t.Error("ResolveHosts should be true by default")
	}
}

func TestNewAnalyzer_Defaults(t *testing.T) {
	a := NewAnalyzer(Options{})
	if a.opts.MaxHops != 30 {
		t.Errorf("expected MaxHops 30, got %d", a.opts.MaxHops)
	}
	if a.opts.ProbesPerHop != 5 {
		t.Errorf("expected ProbesPerHop 5, got %d", a.opts.ProbesPerHop)
	}
}

func TestHopQuality_Perfect(t *testing.T) {
	a := NewAnalyzer(DefaultOptions())
	hop := Hop{
		Sent:       5,
		Received:   5,
		PacketLoss: 0,
		AvgRTT:     10 * time.Millisecond,
		Jitter:     1 * time.Millisecond,
	}
	score := a.calculateHopQuality(hop)
	if score < 95 {
		t.Errorf("expected high quality score, got %.0f", score)
	}
}

func TestHopQuality_HighLoss(t *testing.T) {
	a := NewAnalyzer(DefaultOptions())
	hop := Hop{
		Sent:       5,
		Received:   2,
		PacketLoss: 60,
		AvgRTT:     10 * time.Millisecond,
	}
	score := a.calculateHopQuality(hop)
	if score > 50 {
		t.Errorf("expected low quality score for high loss, got %.0f", score)
	}
}

func TestHopQuality_HighLatency(t *testing.T) {
	a := NewAnalyzer(DefaultOptions())
	hop := Hop{
		Sent:       5,
		Received:   5,
		PacketLoss: 0,
		AvgRTT:     500 * time.Millisecond,
	}
	score := a.calculateHopQuality(hop)
	if score > 80 {
		t.Errorf("expected reduced quality for high latency, got %.0f", score)
	}
}

func TestAvgDuration(t *testing.T) {
	durations := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}
	avg := avgDuration(durations)
	expected := 20 * time.Millisecond
	if avg != expected {
		t.Errorf("expected %v, got %v", expected, avg)
	}
}

func TestMinDuration(t *testing.T) {
	durations := []time.Duration{30 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}
	min := minDuration(durations)
	expected := 10 * time.Millisecond
	if min != expected {
		t.Errorf("expected %v, got %v", expected, min)
	}
}

func TestMaxDuration(t *testing.T) {
	durations := []time.Duration{10 * time.Millisecond, 30 * time.Millisecond, 20 * time.Millisecond}
	max := maxDuration(durations)
	expected := 30 * time.Millisecond
	if max != expected {
		t.Errorf("expected %v, got %v", expected, max)
	}
}

func TestPathResult_Format(t *testing.T) {
	result := &PathResult{
		Target:       "example.com",
		ResolvedIP:   net.ParseIP("93.184.216.34"),
		TotalHops:    5,
		TotalLatency: 50 * time.Millisecond,
		QualityScore: 85,
		Hops: []Hop{
			{Number: 1, IP: net.ParseIP("192.168.1.1"), AvgRTT: 5 * time.Millisecond, PacketLoss: 0, QualityScore: 100},
			{Number: 2, IP: net.ParseIP("10.0.0.1"), AvgRTT: 15 * time.Millisecond, PacketLoss: 0, QualityScore: 95},
		},
		Analysis: []string{"✓ Excellent path quality"},
	}

	formatted := result.Format()
	if formatted == "" {
		t.Error("Format() returned empty string")
	}
	if !containsStr(formatted, "example.com") {
		t.Error("Format() missing target")
	}
	if !containsStr(formatted, "192.168.1.1") {
		t.Error("Format() missing hop IP")
	}
}

func TestGetWorstHops(t *testing.T) {
	result := &PathResult{
		Hops: []Hop{
			{Number: 1, QualityScore: 100},
			{Number: 2, QualityScore: 50},
			{Number: 3, QualityScore: 75},
			{Number: 4, QualityScore: 25},
		},
	}

	worst := result.GetWorstHops(2)
	if len(worst) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(worst))
	}
	if worst[0].QualityScore != 25 {
		t.Errorf("expected worst hop quality 25, got %.0f", worst[0].QualityScore)
	}
	if worst[1].QualityScore != 50 {
		t.Errorf("expected second worst hop quality 50, got %.0f", worst[1].QualityScore)
	}
}

func TestGetWorstHops_Empty(t *testing.T) {
	result := &PathResult{}
	worst := result.GetWorstHops(5)
	if worst != nil {
		t.Error("expected nil for empty hops")
	}
}

func TestAnalyze_Integration(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxHops = 10
	opts.ProbesPerHop = 2
	opts.Interval = 10 * time.Millisecond
	opts.ResolveHosts = false

	a := NewAnalyzer(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := a.Analyze(ctx, "localhost")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result.Target != "localhost" {
		t.Errorf("expected target localhost, got %s", result.Target)
	}
	if result.TotalHops == 0 {
		t.Error("expected at least one hop")
	}
}

func TestGenerateAnalysis(t *testing.T) {
	a := NewAnalyzer(DefaultOptions())

	tests := []struct {
		name     string
		quality  float64
		expected string
	}{
		{"excellent", 95, "Excellent"},
		{"good", 75, "Good"},
		{"fair", 55, "Fair"},
		{"poor", 30, "Poor"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &PathResult{QualityScore: tt.quality}
			analysis := a.generateAnalysis(result)
			if len(analysis) == 0 {
				t.Fatal("expected analysis")
			}
			if !containsStr(analysis[0], tt.expected) {
				t.Errorf("expected analysis containing %s, got %s", tt.expected, analysis[0])
			}
		})
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstr(s, substr))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
