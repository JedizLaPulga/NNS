package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeNoRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 5
	opts.Delay = 0

	s := Probe(context.Background(), opts)
	if s.TotalRequests != 5 {
		t.Errorf("expected 5 requests, got %d", s.TotalRequests)
	}
	if s.LimitedCount != 0 {
		t.Errorf("expected 0 limited, got %d", s.LimitedCount)
	}
	if s.HasRateLimiting {
		t.Error("should not detect rate limiting")
	}
}

func TestProbe429Detection(t *testing.T) {
	var count int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&count, 1)
		if n > 3 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 6
	opts.Delay = 0

	s := Probe(context.Background(), opts)
	if s.SuccessCount != 3 {
		t.Errorf("expected 3 successes, got %d", s.SuccessCount)
	}
	if s.LimitedCount != 3 {
		t.Errorf("expected 3 limited, got %d", s.LimitedCount)
	}
	if !s.HasRateLimiting {
		t.Error("should detect rate limiting")
	}
}

func TestProbeRateLimitHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", "95")
		w.Header().Set("X-RateLimit-Reset", "1700000000")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 2
	opts.Delay = 0

	s := Probe(context.Background(), opts)
	if s.DetectedLimit != 100 {
		t.Errorf("expected limit 100, got %d", s.DetectedLimit)
	}
	if !s.HasRateLimiting {
		t.Error("should detect rate limiting via headers")
	}
	if len(s.Headers) == 0 {
		t.Error("expected discovered headers")
	}
}

func TestProbeContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := DefaultOptions(srv.URL)
	opts.Count = 100
	opts.Delay = 0

	s := Probe(ctx, opts)
	if s.TotalRequests >= 100 {
		t.Error("should have stopped early due to context cancel")
	}
}

func TestProbeInvalidURL(t *testing.T) {
	opts := DefaultOptions("http://192.0.2.1:1/nonexistent")
	opts.Count = 1
	opts.Timeout = 500 * time.Millisecond
	opts.Delay = 0

	s := Probe(context.Background(), opts)
	if s.ErrorCount == 0 {
		t.Error("expected errors for unreachable URL")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions("http://example.com")
	if opts.URL != "http://example.com" {
		t.Errorf("unexpected URL: %s", opts.URL)
	}
	if opts.Method != "GET" {
		t.Errorf("unexpected method: %s", opts.Method)
	}
	if opts.Count != 30 {
		t.Errorf("unexpected count: %d", opts.Count)
	}
	if opts.Concurrent != 1 {
		t.Errorf("unexpected concurrent: %d", opts.Concurrent)
	}
}

func TestParseRateLimitHeadersMissing(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	p := parseRateLimitHeaders(resp)
	if p != nil {
		t.Error("expected nil when no rate limit headers")
	}
}

func TestParseRateLimitHeadersPresent(t *testing.T) {
	resp := &http.Response{Header: http.Header{
		"X-Ratelimit-Limit":     {"50"},
		"X-Ratelimit-Remaining": {"42"},
		"X-Ratelimit-Reset":     {"1700000000"},
	}}
	p := parseRateLimitHeaders(resp)
	if p == nil {
		t.Fatal("expected policy")
	}
	if p.Limit != 50 {
		t.Errorf("expected limit 50, got %d", p.Limit)
	}
	if p.Remaining != 42 {
		t.Errorf("expected remaining 42, got %d", p.Remaining)
	}
}

func TestFindRateLimitHeaders(t *testing.T) {
	resp := &http.Response{Header: http.Header{
		"X-Ratelimit-Limit":     {"100"},
		"X-Ratelimit-Remaining": {"99"},
		"Retry-After":           {"30"},
		"Content-Type":          {"text/html"},
	}}
	found := FindRateLimitHeaders(resp)
	if len(found) != 3 {
		t.Errorf("expected 3 rate limit headers, got %d", len(found))
	}
	if _, ok := found["Content-Type"]; ok {
		t.Error("Content-Type should not be rate limit header")
	}
}

func TestFormatSummaryNoLimit(t *testing.T) {
	s := Summary{
		URL:           "http://test.com",
		TotalRequests: 5,
		SuccessCount:  5,
		Results:       []ProbeResult{{Latency: time.Millisecond}},
	}
	finalize(&s, 5*time.Millisecond)
	out := FormatSummary(s)
	if !strings.Contains(out, "No rate limiting detected") {
		t.Error("expected no rate limiting message")
	}
}

func TestFormatSummaryWithLimit(t *testing.T) {
	s := Summary{
		URL:             "http://test.com",
		TotalRequests:   10,
		SuccessCount:    7,
		LimitedCount:    3,
		FirstLimitedAt:  8,
		DetectedLimit:   100,
		DetectedWindow:  "1m",
		HasRateLimiting: true,
		Headers:         []string{"X-RateLimit-Limit"},
		Results:         []ProbeResult{{Latency: time.Millisecond}},
	}
	finalize(&s, 10*time.Millisecond)
	out := FormatSummary(s)
	if !strings.Contains(out, "Rate Limiting DETECTED") {
		t.Error("expected rate limiting detected message")
	}
	if !strings.Contains(out, "100") {
		t.Error("expected limit value")
	}
}

func TestFormatResults(t *testing.T) {
	results := []ProbeResult{
		{RequestNum: 1, StatusCode: 200, Latency: 50 * time.Millisecond,
			Policy: &Policy{Limit: 100, Remaining: 99}},
		{RequestNum: 2, StatusCode: 429, Latency: 30 * time.Millisecond, Limited: true},
		{RequestNum: 3, Latency: 0, Error: "connection refused"},
	}
	out := FormatResults(results)
	if !strings.Contains(out, "OK") {
		t.Error("expected OK status")
	}
	if !strings.Contains(out, "429") {
		t.Error("expected 429")
	}
	if !strings.Contains(out, "connection refused") {
		t.Error("expected error message")
	}
}

func TestProbeWithCustomHeaders(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 1
	opts.Delay = 0
	opts.Headers = map[string]string{"Authorization": "Bearer test-token"}

	Probe(context.Background(), opts)
	if gotHeader != "Bearer test-token" {
		t.Errorf("expected auth header, got: %s", gotHeader)
	}
}

func TestProbeLatencyTracking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 3
	opts.Delay = 0

	s := Probe(context.Background(), opts)
	if s.AvgLatency < 0 {
		t.Error("avg latency should be non-negative")
	}
	if s.MinLatency < 0 {
		t.Error("min latency should be non-negative")
	}
	if s.MaxLatency < s.MinLatency {
		t.Error("max should be >= min")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("should not truncate short strings")
	}
	if truncate("a very long string here", 10) != "a very lon..." {
		t.Errorf("unexpected truncation: %s", truncate("a very long string here", 10))
	}
}

func TestMax(t *testing.T) {
	if max(1, 2) != 2 {
		t.Error("max(1,2) should be 2")
	}
	if max(5, 3) != 5 {
		t.Error("max(5,3) should be 5")
	}
}

func TestProbeRateLimitWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Window", "1m")
		w.Header().Set("X-RateLimit-Remaining", "58")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 2
	opts.Delay = 0

	s := Probe(context.Background(), opts)
	if s.DetectedWindow != "1m" {
		t.Errorf("expected window '1m', got '%s'", s.DetectedWindow)
	}
}

func TestProbeMethodOption(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Method = "HEAD"
	opts.Count = 1
	opts.Delay = 0

	Probe(context.Background(), opts)
	if gotMethod != "HEAD" {
		t.Errorf("expected HEAD, got %s", gotMethod)
	}
}

func TestProbeRetryAfterHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 1
	opts.Delay = 0

	s := Probe(context.Background(), opts)
	if s.LimitedCount != 1 {
		t.Error("expected 1 limited")
	}
	if len(s.Results) == 0 {
		t.Fatal("expected results")
	}
	if s.Results[0].Policy == nil {
		t.Fatal("expected policy with Retry-After")
	}
	if s.Results[0].Policy.RetryStr != "120" {
		t.Errorf("expected RetryStr '120', got '%s'", s.Results[0].Policy.RetryStr)
	}
}

func TestFinalizeEmpty(t *testing.T) {
	s := &Summary{}
	finalize(s, 0)
	if s.HasRateLimiting {
		t.Error("empty should not be rate limited")
	}
}

func TestProbeUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 1
	opts.Delay = 0

	Probe(context.Background(), opts)
	if gotUA != "nns/ratelimit-probe" {
		t.Errorf("expected nns user agent, got: %s", gotUA)
	}
}

func TestProbeConcurrent(t *testing.T) {
	var count int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions(srv.URL)
	opts.Count = 10
	opts.Concurrent = 5
	opts.Delay = 0

	s := Probe(context.Background(), opts)
	if s.TotalRequests != 10 {
		t.Errorf("expected 10 requests, got %d", s.TotalRequests)
	}
	if atomic.LoadInt64(&count) != 10 {
		t.Errorf("expected 10 server hits, got %d", count)
	}
}

func TestFormatSummaryHeaders(t *testing.T) {
	s := Summary{
		URL:             "http://test.com",
		TotalRequests:   1,
		HasRateLimiting: true,
		Headers:         []string{"X-RateLimit-Limit", "X-RateLimit-Remaining"},
		Results:         []ProbeResult{{Latency: time.Millisecond}},
	}
	finalize(&s, time.Millisecond)
	out := FormatSummary(s)
	if !strings.Contains(out, "Headers Found") {
		t.Error("expected headers section")
	}
}

func TestFormatResultsEmpty(t *testing.T) {
	out := FormatResults(nil)
	if !strings.Contains(out, "#") {
		t.Error("expected header row")
	}
	_ = fmt.Sprintf("output: %s", out)
}
