package dnsperf

import (
	"context"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.QueryCount != 10 {
		t.Errorf("expected 10 queries, got %d", opts.QueryCount)
	}
	if opts.Concurrency != 5 {
		t.Errorf("expected 5 concurrency, got %d", opts.Concurrency)
	}
	if opts.QueryType != "A" {
		t.Errorf("expected A query type, got %s", opts.QueryType)
	}
	if len(opts.Resolvers) != 4 {
		t.Errorf("expected 4 resolvers, got %d", len(opts.Resolvers))
	}
}

func TestNewBenchmark_Defaults(t *testing.T) {
	b := NewBenchmark(Options{})
	if b.opts.QueryCount != 10 {
		t.Errorf("expected 10, got %d", b.opts.QueryCount)
	}
	if b.opts.QueryType != "A" {
		t.Errorf("expected A, got %s", b.opts.QueryType)
	}
}

func TestCommonResolvers(t *testing.T) {
	if len(CommonResolvers) < 5 {
		t.Errorf("expected at least 5 common resolvers, got %d", len(CommonResolvers))
	}

	// Check Google is included
	found := false
	for _, r := range CommonResolvers {
		if r.Name == "Google" {
			found = true
			if r.Address != "8.8.8.8:53" {
				t.Errorf("unexpected Google address: %s", r.Address)
			}
			break
		}
	}
	if !found {
		t.Error("Google resolver not found")
	}
}

func TestPercentile(t *testing.T) {
	durations := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
	}

	tests := []struct {
		p        int
		expected time.Duration
	}{
		{50, 30 * time.Millisecond},
		{90, 40 * time.Millisecond},
		{0, 10 * time.Millisecond},
	}

	for _, tt := range tests {
		result := percentile(durations, tt.p)
		if result != tt.expected {
			t.Errorf("P%d: expected %v, got %v", tt.p, tt.expected, result)
		}
	}
}

func TestPercentile_Empty(t *testing.T) {
	result := percentile([]time.Duration{}, 50)
	if result != 0 {
		t.Errorf("expected 0 for empty, got %v", result)
	}
}

func TestBenchmarkResult_Format(t *testing.T) {
	result := &BenchmarkResult{
		Domain:    "example.com",
		QueryType: "A",
		Duration:  500 * time.Millisecond,
		Results: []Result{
			{
				Resolver:   Resolver{Name: "Google", Address: "8.8.8.8:53"},
				Queries:    10,
				Successful: 10,
				AvgLatency: 25 * time.Millisecond,
				MinLatency: 20 * time.Millisecond,
				MaxLatency: 35 * time.Millisecond,
				P99Latency: 34 * time.Millisecond,
				ErrorRate:  0,
			},
			{
				Resolver:   Resolver{Name: "Cloudflare", Address: "1.1.1.1:53"},
				Queries:    10,
				Successful: 9,
				Failed:     1,
				AvgLatency: 30 * time.Millisecond,
				MinLatency: 22 * time.Millisecond,
				MaxLatency: 50 * time.Millisecond,
				P99Latency: 48 * time.Millisecond,
				ErrorRate:  10,
			},
		},
	}
	result.Best = &result.Results[0]

	formatted := result.Format()
	if formatted == "" {
		t.Error("Format() returned empty")
	}
	if !containsStr(formatted, "example.com") {
		t.Error("missing domain")
	}
	if !containsStr(formatted, "Google") {
		t.Error("missing resolver name")
	}
	if !containsStr(formatted, "★") {
		t.Error("missing best indicator")
	}
}

func TestBenchmarkResult_FormatCompact(t *testing.T) {
	result := &BenchmarkResult{
		Domain: "test.com",
		Results: []Result{
			{Resolver: Resolver{Name: "R1"}, AvgLatency: 10 * time.Millisecond},
			{Resolver: Resolver{Name: "R2"}, AvgLatency: 20 * time.Millisecond},
		},
	}

	formatted := result.FormatCompact()
	if !containsStr(formatted, "R1") {
		t.Error("missing resolver")
	}
	if !containsStr(formatted, "1.") {
		t.Error("missing ranking")
	}
}

func TestGetRanking(t *testing.T) {
	result := &BenchmarkResult{
		Results: []Result{
			{Resolver: Resolver{Name: "First"}},
			{Resolver: Resolver{Name: "Second"}},
			{Resolver: Resolver{Name: "Third"}},
		},
	}

	ranking := result.GetRanking()
	if len(ranking) != 3 {
		t.Fatalf("expected 3, got %d", len(ranking))
	}
	if ranking[0] != "First" {
		t.Errorf("expected First, got %s", ranking[0])
	}
}

func TestCompareResolvers_Faster(t *testing.T) {
	a := &Result{
		Resolver:   Resolver{Name: "Fast"},
		AvgLatency: 10 * time.Millisecond,
	}
	b := &Result{
		Resolver:   Resolver{Name: "Slow"},
		AvgLatency: 20 * time.Millisecond,
	}

	comparison := CompareResolvers(a, b)
	if !containsStr(comparison, "Fast") {
		t.Error("should mention faster resolver")
	}
	if !containsStr(comparison, "faster") {
		t.Error("should say 'faster'")
	}
}

func TestRun_NoDomain(t *testing.T) {
	b := NewBenchmark(DefaultOptions())
	_, err := b.Run(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty domain")
	}
}

func TestRun_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	opts := Options{
		Resolvers: []Resolver{
			{Name: "Google", Address: "8.8.8.8:53"},
		},
		QueryCount:  2,
		Concurrency: 1,
		Timeout:     2 * time.Second,
		QueryType:   "A",
	}

	b := NewBenchmark(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := b.Run(ctx, "google.com")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Domain != "google.com" {
		t.Errorf("expected google.com, got %s", result.Domain)
	}
	if len(result.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Results))
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
