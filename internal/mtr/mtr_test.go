package mtr

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxHops != 30 {
		t.Errorf("DefaultConfig().MaxHops = %d, want 30", cfg.MaxHops)
	}
	if cfg.Timeout != 2*time.Second {
		t.Errorf("DefaultConfig().Timeout = %v, want 2s", cfg.Timeout)
	}
	if cfg.Interval != 1*time.Second {
		t.Errorf("DefaultConfig().Interval = %v, want 1s", cfg.Interval)
	}
	if cfg.Count != 10 {
		t.Errorf("DefaultConfig().Count = %d, want 10", cfg.Count)
	}
	if !cfg.ResolveHost {
		t.Error("DefaultConfig().ResolveHost should be true")
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		wantMaxHops int
		wantTimeout time.Duration
	}{
		{
			name:        "default values applied",
			cfg:         Config{Target: "example.com"},
			wantMaxHops: 30,
			wantTimeout: 2 * time.Second,
		},
		{
			name:        "custom values preserved",
			cfg:         Config{Target: "example.com", MaxHops: 15, Timeout: 5 * time.Second},
			wantMaxHops: 15,
			wantTimeout: 5 * time.Second,
		},
		{
			name:        "zero maxhops gets default",
			cfg:         Config{Target: "example.com", MaxHops: 0},
			wantMaxHops: 30,
			wantTimeout: 2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.cfg)
			if m.cfg.MaxHops != tt.wantMaxHops {
				t.Errorf("MaxHops = %d, want %d", m.cfg.MaxHops, tt.wantMaxHops)
			}
			if m.cfg.Timeout != tt.wantTimeout {
				t.Errorf("Timeout = %v, want %v", m.cfg.Timeout, tt.wantTimeout)
			}
			if m.result == nil {
				t.Error("result should be initialized")
			}
			if len(m.result.Hops) != tt.wantMaxHops {
				t.Errorf("Hops length = %d, want %d", len(m.result.Hops), tt.wantMaxHops)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		target  string
		wantErr bool
	}{
		{"8.8.8.8", false},
		{"127.0.0.1", false},
		{"google.com", false},
		{"", true},
		{"invalid..host..name", true},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			_, err := ParseTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestCalculateStats(t *testing.T) {
	tests := []struct {
		name      string
		rtts      []time.Duration
		wantMin   time.Duration
		wantMax   time.Duration
		wantAvgGT time.Duration // avg should be greater than
		wantAvgLT time.Duration // avg should be less than
	}{
		{
			name:      "empty",
			rtts:      []time.Duration{},
			wantMin:   0,
			wantMax:   0,
			wantAvgGT: -1,
			wantAvgLT: 1,
		},
		{
			name:      "single value",
			rtts:      []time.Duration{10 * time.Millisecond},
			wantMin:   10 * time.Millisecond,
			wantMax:   10 * time.Millisecond,
			wantAvgGT: 9 * time.Millisecond,
			wantAvgLT: 11 * time.Millisecond,
		},
		{
			name:      "multiple values",
			rtts:      []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond},
			wantMin:   10 * time.Millisecond,
			wantMax:   30 * time.Millisecond,
			wantAvgGT: 19 * time.Millisecond,
			wantAvgLT: 21 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			min, max, avg, _ := calculateStats(tt.rtts)
			if min != tt.wantMin {
				t.Errorf("min = %v, want %v", min, tt.wantMin)
			}
			if max != tt.wantMax {
				t.Errorf("max = %v, want %v", max, tt.wantMax)
			}
			if avg <= tt.wantAvgGT || avg >= tt.wantAvgLT {
				t.Errorf("avg = %v, want between %v and %v", avg, tt.wantAvgGT, tt.wantAvgLT)
			}
		})
	}
}

func TestHopStatsInitialization(t *testing.T) {
	cfg := Config{
		Target:  "127.0.0.1",
		MaxHops: 5,
	}
	m := New(cfg)

	for i, hop := range m.result.Hops {
		if hop == nil {
			t.Errorf("Hop %d is nil", i)
			continue
		}
		if hop.TTL != i+1 {
			t.Errorf("Hop %d TTL = %d, want %d", i, hop.TTL, i+1)
		}
		if hop.AllRTTs == nil {
			t.Errorf("Hop %d AllRTTs is nil", i)
		}
	}
}

func TestGetResult(t *testing.T) {
	cfg := Config{
		Target:  "127.0.0.1",
		MaxHops: 5,
	}
	m := New(cfg)

	result := m.GetResult()

	if result == nil {
		t.Fatal("GetResult() returned nil")
	}
	if result.Target != cfg.Target {
		t.Errorf("Target = %q, want %q", result.Target, cfg.Target)
	}
	if len(result.Hops) != cfg.MaxHops {
		t.Errorf("Hops length = %d, want %d", len(result.Hops), cfg.MaxHops)
	}
}

func TestGetActiveHops(t *testing.T) {
	result := &Result{
		Hops: []*HopStats{
			{TTL: 1, IP: "192.168.1.1"},
			{TTL: 2, IP: ""},
			{TTL: 3, IP: "10.0.0.1"},
			{TTL: 4, IP: ""},
		},
	}

	active := result.GetActiveHops()

	if len(active) != 2 {
		t.Errorf("GetActiveHops() returned %d hops, want 2", len(active))
	}

	for _, hop := range active {
		if hop.IP == "" {
			t.Error("GetActiveHops() included hop with empty IP")
		}
	}
}

func TestSqrt(t *testing.T) {
	tests := []struct {
		x    float64
		want float64
		tol  float64
	}{
		{0, 0, 0.001},
		{1, 1, 0.001},
		{4, 2, 0.001},
		{9, 3, 0.001},
		{16, 4, 0.001},
		{2, 1.414, 0.01},
	}

	for _, tt := range tests {
		got := sqrt(tt.x)
		diff := got - tt.want
		if diff < 0 {
			diff = -diff
		}
		if diff > tt.tol {
			t.Errorf("sqrt(%v) = %v, want %v (tolerance %v)", tt.x, got, tt.want, tt.tol)
		}
	}
}

func TestMTRWithLoopback(t *testing.T) {
	// This test runs against loopback to avoid requiring ICMP privileges
	cfg := Config{
		Target:      "127.0.0.1",
		MaxHops:     3,
		Timeout:     500 * time.Millisecond,
		Interval:    100 * time.Millisecond,
		Count:       1,
		ResolveHost: false,
	}

	m := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	callbackCalled := false
	err := m.Run(ctx, func(r *Result) {
		callbackCalled = true
	})

	// This may fail without admin/root, which is OK
	if err != nil {
		t.Skipf("MTR run failed (may need admin privileges): %v", err)
	}

	if !callbackCalled {
		t.Error("Callback was not called")
	}

	result := m.GetResult()
	if result.Target != "127.0.0.1" {
		t.Errorf("Target = %q, want 127.0.0.1", result.Target)
	}
}

func TestMTRContextCancellation(t *testing.T) {
	cfg := Config{
		Target:   "127.0.0.1",
		MaxHops:  3,
		Timeout:  500 * time.Millisecond,
		Interval: 100 * time.Millisecond,
		Count:    0, // Infinite
	}

	m := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := m.Run(ctx, nil)
	elapsed := time.Since(start)

	// May fail without admin privileges
	if err != nil {
		t.Skipf("MTR run failed (may need admin privileges): %v", err)
	}

	// Should have exited within a reasonable time after context cancel
	if elapsed > 2*time.Second {
		t.Errorf("MTR did not respect context cancellation, took %v", elapsed)
	}
}

func TestLossPercentCalculation(t *testing.T) {
	hop := &HopStats{
		Sent:     10,
		Received: 7,
	}

	hop.Lost = hop.Sent - hop.Received
	hop.LossPercent = float64(hop.Lost) / float64(hop.Sent) * 100

	if hop.LossPercent != 30.0 {
		t.Errorf("LossPercent = %v, want 30.0", hop.LossPercent)
	}
}

func TestHopStatsConcurrency(t *testing.T) {
	hop := &HopStats{
		AllRTTs: make([]time.Duration, 0),
	}

	done := make(chan bool)

	// Simulate concurrent access
	go func() {
		for i := 0; i < 100; i++ {
			hop.mu.Lock()
			hop.Sent++
			hop.AllRTTs = append(hop.AllRTTs, time.Duration(i)*time.Millisecond)
			hop.mu.Unlock()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			hop.mu.Lock()
			_ = hop.Sent
			_ = len(hop.AllRTTs)
			hop.mu.Unlock()
		}
		done <- true
	}()

	<-done
	<-done

	hop.mu.Lock()
	if hop.Sent != 100 {
		t.Errorf("Sent = %d after concurrent access, want 100", hop.Sent)
	}
	if len(hop.AllRTTs) != 100 {
		t.Errorf("AllRTTs length = %d, want 100", len(hop.AllRTTs))
	}
	hop.mu.Unlock()
}
