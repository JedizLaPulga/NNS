package resolvers

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.QueryCount != 5 {
		t.Errorf("DefaultConfig().QueryCount = %d, want 5", cfg.QueryCount)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("DefaultConfig().Timeout = %v, want 5s", cfg.Timeout)
	}
	if cfg.TestDomain != "google.com" {
		t.Errorf("DefaultConfig().TestDomain = %s, want google.com", cfg.TestDomain)
	}
}

func TestNew(t *testing.T) {
	comp := New(Config{})

	if comp.config.QueryCount != 5 {
		t.Errorf("New().config.QueryCount = %d, want 5", comp.config.QueryCount)
	}
	if len(comp.config.Resolvers) == 0 {
		t.Error("New().config.Resolvers should not be empty")
	}
}

func TestPublicResolvers(t *testing.T) {
	if len(PublicResolvers) == 0 {
		t.Error("PublicResolvers should not be empty")
	}

	// Check for well-known resolvers
	hasGoogle := false
	hasCloudflare := false
	for _, r := range PublicResolvers {
		if r.Provider == "Google" {
			hasGoogle = true
		}
		if r.Provider == "Cloudflare" {
			hasCloudflare = true
		}
	}

	if !hasGoogle {
		t.Error("PublicResolvers should contain Google")
	}
	if !hasCloudflare {
		t.Error("PublicResolvers should contain Cloudflare")
	}
}

func TestCalculateStats(t *testing.T) {
	comp := New(DefaultConfig())

	result := &TestResult{
		Queries:   5,
		Latencies: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 15 * time.Millisecond},
	}
	result.Successful = 3

	comp.calculateStats(result)

	if !result.Reachable {
		t.Error("calculateStats should set Reachable = true")
	}
	if result.MinLatency != 10*time.Millisecond {
		t.Errorf("MinLatency = %v, want 10ms", result.MinLatency)
	}
	if result.MaxLatency != 20*time.Millisecond {
		t.Errorf("MaxLatency = %v, want 20ms", result.MaxLatency)
	}
	if result.SuccessRate != 60 {
		t.Errorf("SuccessRate = %.0f, want 60", result.SuccessRate)
	}
}

func TestCalculateStatsEmpty(t *testing.T) {
	comp := New(DefaultConfig())

	result := &TestResult{Queries: 5}
	comp.calculateStats(result)

	if result.Reachable {
		t.Error("Empty latencies should set Reachable = false")
	}
	if result.Score != 999999 {
		t.Errorf("Empty latencies should set Score = 999999, got %f", result.Score)
	}
}

func TestCompareResultFormat(t *testing.T) {
	result := &CompareResult{
		TestDomain: "example.com",
		QueryCount: 5,
		Duration:   1 * time.Second,
		Results: []TestResult{
			{
				Resolver:    Resolver{Name: "Test DNS", Address: "1.2.3.4:53"},
				Reachable:   true,
				AvgLatency:  15 * time.Millisecond,
				MinLatency:  10 * time.Millisecond,
				MaxLatency:  20 * time.Millisecond,
				SuccessRate: 100,
			},
		},
	}

	output := result.Format()

	if output == "" {
		t.Error("Format() returned empty string")
	}
	if len(output) < 50 {
		t.Error("Format() output too short")
	}
}

func TestCompareContextCancellation(t *testing.T) {
	cfg := Config{
		Resolvers:  []Resolver{{Name: "Test", Address: "10.255.255.1:53"}},
		QueryCount: 1,
		Timeout:    100 * time.Millisecond,
	}
	comp := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := comp.Compare(ctx)
	// Should complete (possibly with incomplete results) but not hang
	if err != nil && err != context.DeadlineExceeded {
		t.Logf("Compare returned error: %v", err)
	}
}

func TestFindRecommendations(t *testing.T) {
	comp := New(DefaultConfig())

	result := &CompareResult{
		Results: []TestResult{
			{Resolver: Resolver{Name: "Slow", Privacy: "logging"}, Reachable: true, Score: 100},
			{Resolver: Resolver{Name: "Fast", Privacy: "no-logging"}, Reachable: true, Score: 50},
		},
	}

	comp.findRecommendations(result)

	if result.Recommended == nil {
		t.Error("Recommended should not be nil")
	}
	if result.BestPrivacy == nil {
		t.Error("BestPrivacy should not be nil")
	}
}
