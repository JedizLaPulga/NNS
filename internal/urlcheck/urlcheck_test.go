package urlcheck

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", cfg.Timeout)
	}
	if cfg.Concurrency != 10 {
		t.Errorf("expected concurrency 10, got %d", cfg.Concurrency)
	}
}

func TestNew(t *testing.T) {
	checker := New(Config{})
	if checker.config.Timeout != 10*time.Second {
		t.Errorf("expected default timeout, got %v", checker.config.Timeout)
	}
}

func TestParseTargets(t *testing.T) {
	urls := []string{"google.com", "https://github.com", "http://example.com"}
	targets := ParseTargets(urls)

	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
	if targets[0].URL != "https://google.com" {
		t.Errorf("expected https scheme added, got %s", targets[0].URL)
	}
}

func TestResultIsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		result   Result
		expected bool
	}{
		{"200 OK", Result{StatusCode: 200}, true},
		{"301 Redirect", Result{StatusCode: 301}, true},
		{"404 NotFound", Result{StatusCode: 404}, false},
		{"500 Error", Result{StatusCode: 500}, false},
		{"With Error", Result{Error: context.DeadlineExceeded}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsHealthy(); got != tt.expected {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFormatResult(t *testing.T) {
	r := Result{
		URL:          "https://example.com",
		StatusCode:   200,
		ResponseTime: 50 * time.Millisecond,
		ContentSize:  1024,
	}
	formatted := FormatResult(r)
	if formatted == "" {
		t.Error("expected non-empty formatted result")
	}
}

func TestFormatResultWithError(t *testing.T) {
	r := Result{
		URL:   "https://example.com",
		Error: context.DeadlineExceeded,
	}
	formatted := FormatResult(r)
	if formatted == "" {
		t.Error("expected non-empty formatted result")
	}
}

func TestSummarize(t *testing.T) {
	results := []Result{
		{StatusCode: 200, ResponseTime: 50 * time.Millisecond},
		{StatusCode: 200, ResponseTime: 100 * time.Millisecond},
		{StatusCode: 500, ResponseTime: 200 * time.Millisecond},
	}
	s := Summarize(results)

	if s.Total != 3 {
		t.Errorf("expected total 3, got %d", s.Total)
	}
	if s.Healthy != 2 {
		t.Errorf("expected healthy 2, got %d", s.Healthy)
	}
	if s.Unhealthy != 1 {
		t.Errorf("expected unhealthy 1, got %d", s.Unhealthy)
	}
}

func TestFormatSummary(t *testing.T) {
	s := Summary{
		Total:     10,
		Healthy:   8,
		Unhealthy: 2,
		AvgTime:   100 * time.Millisecond,
	}
	formatted := FormatSummary(s)
	if formatted == "" {
		t.Error("expected non-empty formatted summary")
	}
}

func TestSortByResponseTime(t *testing.T) {
	results := []Result{
		{URL: "slow", ResponseTime: 500 * time.Millisecond},
		{URL: "fast", ResponseTime: 50 * time.Millisecond},
		{URL: "medium", ResponseTime: 200 * time.Millisecond},
	}
	SortByResponseTime(results)

	if results[0].URL != "fast" {
		t.Error("expected fastest first")
	}
	if results[2].URL != "slow" {
		t.Error("expected slowest last")
	}
}

func TestCommonEndpoints(t *testing.T) {
	endpoints := CommonEndpoints()
	if len(endpoints) < 3 {
		t.Error("expected at least 3 common endpoints")
	}
}

func TestCheckNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test")
	}

	checker := New(Config{Timeout: 5 * time.Second})
	ctx := context.Background()

	result := checker.Check(ctx, Target{URL: "https://www.google.com"})
	if result.Error != nil {
		t.Skipf("network unavailable: %v", result.Error)
	}
	if result.StatusCode != 200 {
		t.Logf("unexpected status: %d", result.StatusCode)
	}
}
