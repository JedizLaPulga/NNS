package latency

import (
	"context"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Target:   "example.com",
				Port:     443,
				Interval: time.Second,
				Timeout:  5 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty target",
			cfg: Config{
				Port: 443,
			},
			wantErr: true,
		},
		{
			name: "defaults applied for invalid port",
			cfg: Config{
				Target: "example.com",
				Port:   0, // Should default to 443
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mon, err := New(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && mon == nil {
				t.Error("New() returned nil monitor")
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Port != 443 {
		t.Errorf("DefaultConfig().Port = %d, want 443", cfg.Port)
	}
	if cfg.Interval != time.Second {
		t.Errorf("DefaultConfig().Interval = %v, want 1s", cfg.Interval)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("DefaultConfig().Timeout = %v, want 5s", cfg.Timeout)
	}
}

func TestStats_LossPercent(t *testing.T) {
	tests := []struct {
		name     string
		stats    Stats
		expected float64
	}{
		{
			name:     "no probes",
			stats:    Stats{Sent: 0, Lost: 0},
			expected: 0,
		},
		{
			name:     "no loss",
			stats:    Stats{Sent: 10, Lost: 0},
			expected: 0,
		},
		{
			name:     "50% loss",
			stats:    Stats{Sent: 10, Lost: 5},
			expected: 50,
		},
		{
			name:     "100% loss",
			stats:    Stats{Sent: 10, Lost: 10},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stats.LossPercent()
			if got != tt.expected {
				t.Errorf("LossPercent() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMonitor_RunWithCount(t *testing.T) {
	cfg := Config{
		Target:   "127.0.0.1", // Localhost for testing
		Port:     1,           // Unlikely to be listening, but tests the loop
		Interval: 10 * time.Millisecond,
		Timeout:  50 * time.Millisecond,
		Count:    3,
	}

	mon, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var results []Result
	mon.OnResult(func(r Result) {
		results = append(results, r)
	})

	ctx := context.Background()
	err = mon.Run(ctx)
	if err != nil {
		t.Logf("Run() returned error (expected for non-listening port): %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	// Verify sequence numbers
	for i, r := range results {
		if r.Seq != i+1 {
			t.Errorf("Result[%d].Seq = %d, want %d", i, r.Seq, i+1)
		}
	}
}

func TestMonitor_RunCancellation(t *testing.T) {
	cfg := Config{
		Target:   "127.0.0.1",
		Port:     1,
		Interval: 100 * time.Millisecond,
		Timeout:  50 * time.Millisecond,
		Count:    0, // Infinite
	}

	mon, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = mon.Run(ctx)
	elapsed := time.Since(start)

	if err != context.DeadlineExceeded {
		t.Errorf("Run() error = %v, want context.DeadlineExceeded", err)
	}

	if elapsed > 500*time.Millisecond {
		t.Errorf("Run() took too long: %v", elapsed)
	}
}

func TestMonitor_Stats(t *testing.T) {
	cfg := Config{
		Target:    "127.0.0.1",
		Port:      443,
		Interval:  time.Second,
		Timeout:   time.Second,
		Threshold: 50 * time.Millisecond,
	}

	mon, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Manually add results for testing
	mon.mu.Lock()
	mon.results = []Result{
		{Seq: 1, Latency: 10 * time.Millisecond, Timestamp: time.Now()},
		{Seq: 2, Latency: 20 * time.Millisecond, Timestamp: time.Now()},
		{Seq: 3, Latency: 30 * time.Millisecond, Timestamp: time.Now()},
		{Seq: 4, Latency: 100 * time.Millisecond, Timestamp: time.Now(), Alert: true},
		{Seq: 5, Error: context.DeadlineExceeded, Timestamp: time.Now()},
	}
	mon.mu.Unlock()

	stats := mon.Stats()

	if stats.Sent != 5 {
		t.Errorf("Stats.Sent = %d, want 5", stats.Sent)
	}
	if stats.Received != 4 {
		t.Errorf("Stats.Received = %d, want 4", stats.Received)
	}
	if stats.Lost != 1 {
		t.Errorf("Stats.Lost = %d, want 1", stats.Lost)
	}
	if stats.Min != 10*time.Millisecond {
		t.Errorf("Stats.Min = %v, want 10ms", stats.Min)
	}
	if stats.Max != 100*time.Millisecond {
		t.Errorf("Stats.Max = %v, want 100ms", stats.Max)
	}
	if stats.Alerts != 1 {
		t.Errorf("Stats.Alerts = %d, want 1", stats.Alerts)
	}
}

func TestMonitor_Sparkline(t *testing.T) {
	cfg := Config{
		Target:   "127.0.0.1",
		Port:     443,
		Interval: time.Second,
		Timeout:  time.Second,
	}

	mon, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Empty results
	if spark := mon.Sparkline(10); spark != "" {
		t.Errorf("Sparkline() for empty results = %q, want empty", spark)
	}

	// Add some results
	mon.mu.Lock()
	mon.results = []Result{
		{Seq: 1, Latency: 10 * time.Millisecond},
		{Seq: 2, Latency: 50 * time.Millisecond},
		{Seq: 3, Error: context.DeadlineExceeded},
		{Seq: 4, Latency: 100 * time.Millisecond},
	}
	mon.mu.Unlock()

	spark := mon.Sparkline(10)
	if len(spark) == 0 {
		t.Error("Sparkline() returned empty string for non-empty results")
	}

	// Should contain an error marker
	if !containsRune(spark, '✕') {
		t.Error("Sparkline() should contain error marker ✕")
	}
}

func TestFormatResult(t *testing.T) {
	r := Result{
		Seq:     1,
		Latency: 15500 * time.Microsecond, // 15.5ms
	}
	formatted := FormatResult(r, "example.com")
	if formatted == "" {
		t.Error("FormatResult() returned empty string")
	}
	if !containsSubstring(formatted, "15.50ms") {
		t.Errorf("FormatResult() = %q, expected to contain '15.50ms'", formatted)
	}
}

func TestFormatStats(t *testing.T) {
	s := Stats{
		Sent:     10,
		Received: 8,
		Lost:     2,
		Min:      10 * time.Millisecond,
		Max:      100 * time.Millisecond,
		Avg:      40 * time.Millisecond,
	}
	formatted := FormatStats(s)
	if !containsSubstring(formatted, "20.0% loss") {
		t.Errorf("FormatStats() should contain loss percentage")
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstringHelper(s, sub))
}

func containsSubstringHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
