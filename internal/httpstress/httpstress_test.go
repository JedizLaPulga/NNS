package httpstress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Method != "GET" {
		t.Errorf("expected GET, got %s", opts.Method)
	}
	if opts.Concurrency != 10 {
		t.Errorf("expected 10, got %d", opts.Concurrency)
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", opts.Timeout)
	}
}

func TestNewTester_Defaults(t *testing.T) {
	tester := NewTester(Options{})
	if tester.opts.Concurrency != 10 {
		t.Errorf("expected 10, got %d", tester.opts.Concurrency)
	}
	if tester.opts.Method != "GET" {
		t.Errorf("expected GET, got %s", tester.opts.Method)
	}
}

func TestRun_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	opts := Options{
		URL:           server.URL,
		Concurrency:   2,
		TotalRequests: 10,
		Timeout:       5 * time.Second,
	}

	tester := NewTester(opts)
	stats, err := tester.Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if stats.TotalRequests != 10 {
		t.Errorf("expected 10 requests, got %d", stats.TotalRequests)
	}
	if stats.SuccessRequests != 10 {
		t.Errorf("expected 10 success, got %d", stats.SuccessRequests)
	}
	if stats.StatusCodes[200] != 10 {
		t.Errorf("expected 10 200s, got %d", stats.StatusCodes[200])
	}
}

func TestRun_WithErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	opts := Options{
		URL:           server.URL,
		Concurrency:   2,
		TotalRequests: 5,
	}

	tester := NewTester(opts)
	stats, err := tester.Run(context.Background(), nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if stats.StatusCodes[500] != 5 {
		t.Errorf("expected 5 500s, got %d", stats.StatusCodes[500])
	}
}

func TestRun_Duration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	opts := Options{
		URL:         server.URL,
		Concurrency: 2,
		Duration:    200 * time.Millisecond,
	}

	tester := NewTester(opts)
	start := time.Now()
	_, err := tester.Run(context.Background(), nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if elapsed < 150*time.Millisecond {
		t.Errorf("test ended too quickly: %v", elapsed)
	}
}

func TestRun_Cancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	opts := Options{
		URL:           server.URL,
		Concurrency:   5,
		TotalRequests: 1000,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	tester := NewTester(opts)
	_, err := tester.Run(ctx, nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	results := tester.Results()
	if len(results) >= 1000 {
		t.Error("cancellation should have stopped before all requests")
	}
}

func TestRun_NoURL(t *testing.T) {
	tester := NewTester(Options{})
	_, err := tester.Run(context.Background(), nil)
	if err == nil {
		t.Error("expected error for missing URL")
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

	p50 := percentile(durations, 50)
	if p50 != 30*time.Millisecond {
		t.Errorf("expected P50=30ms, got %v", p50)
	}

	p90 := percentile(durations, 90)
	if p90 != 50*time.Millisecond {
		t.Errorf("expected P90=50ms, got %v", p90)
	}
}

func TestStats_Format(t *testing.T) {
	stats := Stats{
		TotalRequests:   100,
		SuccessRequests: 95,
		FailedRequests:  5,
		RequestsPerSec:  50.5,
		MinLatency:      5 * time.Millisecond,
		AvgLatency:      25 * time.Millisecond,
		MaxLatency:      100 * time.Millisecond,
		P50Latency:      20 * time.Millisecond,
		P90Latency:      80 * time.Millisecond,
		P99Latency:      95 * time.Millisecond,
		StatusCodes:     map[int]int64{200: 95, 500: 5},
	}

	formatted := stats.Format()
	if formatted == "" {
		t.Error("Format() returned empty string")
	}
	if !containsStr(formatted, "100") {
		t.Error("missing total requests")
	}
}

func TestSummarizeError(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"connection timeout", "timeout"},
		{"dial tcp: connection refused", "connection_refused"},
		{"lookup example.com: no such host", "dns_error"},
		{"short", "short"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := summarizeError(errors.New(tt.input))
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestProgress_Callback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	opts := Options{
		URL:         server.URL,
		Concurrency: 2,
		Duration:    300 * time.Millisecond,
	}

	var callbackCount int
	tester := NewTester(opts)
	_, _ = tester.Run(context.Background(), func(current, total int64, stats Stats) {
		callbackCount++
	})

	if callbackCount == 0 {
		t.Error("expected progress callback to be called")
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
