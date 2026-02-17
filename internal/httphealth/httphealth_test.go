package httphealth

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

func TestCheckOnceHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL})
	s := CheckOnce(context.Background(), srv.URL, opts)
	if !s.Healthy {
		t.Error("expected healthy")
	}
	if s.StatusCode != 200 {
		t.Errorf("expected 200, got %d", s.StatusCode)
	}
	if s.Latency <= 0 {
		t.Error("latency should be positive")
	}
}

func TestCheckOnceUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL})
	s := CheckOnce(context.Background(), srv.URL, opts)
	if s.Healthy {
		t.Error("expected unhealthy for 503")
	}
	if s.StatusCode != 503 {
		t.Errorf("expected 503, got %d", s.StatusCode)
	}
}

func TestCheckOnceCustomExpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL})
	opts.ExpectedStatus = 204
	s := CheckOnce(context.Background(), srv.URL, opts)
	if !s.Healthy {
		t.Error("should be healthy with custom expected status")
	}
}

func TestCheckOnceTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL})
	opts.Timeout = 50 * time.Millisecond
	s := CheckOnce(context.Background(), srv.URL, opts)
	if s.Healthy {
		t.Error("should be unhealthy due to timeout")
	}
	if s.Error == "" {
		t.Error("expected error message")
	}
}

func TestCheckOnceInvalidURL(t *testing.T) {
	opts := DefaultOptions(nil)
	s := CheckOnce(context.Background(), "http://192.0.2.1:1/bad", opts)
	if s.Healthy {
		t.Error("should be unhealthy")
	}
	if s.Error == "" {
		t.Error("expected error")
	}
}

func TestCheckOnceCustomHeaders(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Custom")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL})
	opts.Headers = map[string]string{"X-Custom": "test-value"}
	CheckOnce(context.Background(), srv.URL, opts)
	if gotHeader != "test-value" {
		t.Errorf("expected custom header, got: %s", gotHeader)
	}
}

func TestCheckOnceUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL})
	CheckOnce(context.Background(), srv.URL, opts)
	if gotUA != "nns/httphealth" {
		t.Errorf("expected nns user agent, got: %s", gotUA)
	}
}

func TestCheckAll(t *testing.T) {
	var count int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL, srv.URL, srv.URL})
	results := CheckAll(context.Background(), opts)
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
	if atomic.LoadInt64(&count) != 3 {
		t.Errorf("expected 3 server hits, got %d", count)
	}
}

func TestDefaultOptions(t *testing.T) {
	urls := []string{"http://a.com", "http://b.com"}
	opts := DefaultOptions(urls)
	if len(opts.URLs) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(opts.URLs))
	}
	if opts.Interval != 10*time.Second {
		t.Errorf("unexpected interval: %s", opts.Interval)
	}
	if opts.Method != "GET" {
		t.Errorf("unexpected method: %s", opts.Method)
	}
	if opts.ExpectedStatus != 200 {
		t.Errorf("unexpected expected status: %d", opts.ExpectedStatus)
	}
}

func TestAccumulateStats(t *testing.T) {
	statsMap := make(map[string]*EndpointStats)

	results := []Status{
		{URL: "http://a.com", Healthy: true, Latency: 100 * time.Millisecond, StatusCode: 200},
		{URL: "http://b.com", Healthy: false, Latency: 200 * time.Millisecond, StatusCode: 500},
	}
	AccumulateStats(statsMap, results, 10)

	if len(statsMap) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(statsMap))
	}

	st := statsMap["http://a.com"]
	if st.TotalChecks != 1 {
		t.Errorf("expected 1 check, got %d", st.TotalChecks)
	}
	if st.HealthyCount != 1 {
		t.Error("expected 1 healthy")
	}
	if st.Uptime != 100.0 {
		t.Errorf("expected 100%% uptime, got %.1f", st.Uptime)
	}

	st2 := statsMap["http://b.com"]
	if st2.FailedCount != 1 {
		t.Error("expected 1 failed")
	}
	if st2.Uptime != 0.0 {
		t.Errorf("expected 0%% uptime, got %.1f", st2.Uptime)
	}
}

func TestAccumulateStatsMultipleRounds(t *testing.T) {
	statsMap := make(map[string]*EndpointStats)

	for i := 0; i < 3; i++ {
		results := []Status{
			{URL: "http://x.com", Healthy: true, Latency: time.Duration(50+i*10) * time.Millisecond},
		}
		AccumulateStats(statsMap, results, 10)
	}

	st := statsMap["http://x.com"]
	if st.TotalChecks != 3 {
		t.Errorf("expected 3 checks, got %d", st.TotalChecks)
	}
	if st.MaxLatency < st.MinLatency {
		t.Error("max should be >= min")
	}
	if len(st.History) != 3 {
		t.Errorf("expected 3 history entries, got %d", len(st.History))
	}
}

func TestAccumulateStatsHistoryLimit(t *testing.T) {
	statsMap := make(map[string]*EndpointStats)

	for i := 0; i < 20; i++ {
		results := []Status{
			{URL: "http://y.com", Healthy: true, Latency: 10 * time.Millisecond},
		}
		AccumulateStats(statsMap, results, 5)
	}

	st := statsMap["http://y.com"]
	if len(st.History) > 5 {
		t.Errorf("history should be capped at 5, got %d", len(st.History))
	}
}

func TestFormatStatus(t *testing.T) {
	s := Status{URL: "http://example.com", StatusCode: 200, Latency: 50 * time.Millisecond, Healthy: true}
	out := FormatStatus(s)
	if !strings.Contains(out, "✓") {
		t.Error("expected healthy icon")
	}
	if !strings.Contains(out, "200") {
		t.Error("expected status code")
	}
}

func TestFormatStatusError(t *testing.T) {
	s := Status{URL: "http://bad.com", Error: "connection refused", Healthy: false}
	out := FormatStatus(s)
	if !strings.Contains(out, "✗") {
		t.Error("expected unhealthy icon")
	}
	if !strings.Contains(out, "ERROR") {
		t.Error("expected ERROR label")
	}
}

func TestFormatRound(t *testing.T) {
	results := []Status{
		{URL: "http://a.com", StatusCode: 200, Latency: 50 * time.Millisecond, Healthy: true},
		{URL: "http://b.com", StatusCode: 503, Latency: 100 * time.Millisecond, Healthy: false},
	}
	out := FormatRound(results)
	if !strings.Contains(out, "http://a.com") {
		t.Error("expected URL in output")
	}
	if !strings.Contains(out, "Latency") {
		t.Error("expected header row")
	}
}

func TestFormatSummary(t *testing.T) {
	statsMap := map[string]*EndpointStats{
		"http://a.com": {
			URL: "http://a.com", TotalChecks: 10, HealthyCount: 9,
			FailedCount: 1, Uptime: 90.0,
			AvgLatency: 50 * time.Millisecond, MaxLatency: 200 * time.Millisecond,
		},
	}

	out := FormatSummary(statsMap)
	if !strings.Contains(out, "http://a.com") {
		t.Error("expected URL")
	}
	if !strings.Contains(out, "90.0") {
		t.Error("expected uptime")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("should not truncate")
	}
	result := truncate("a very long string that goes on", 10)
	if len(result) > 10 {
		t.Errorf("too long: %s", result)
	}
}

func TestMonitorCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL})
	opts.Interval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	var callCount int64

	go Monitor(ctx, opts, func(results []Status) {
		atomic.AddInt64(&callCount, 1)
	})

	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	count := atomic.LoadInt64(&callCount)
	if count < 1 {
		t.Error("expected at least 1 callback")
	}
	_ = fmt.Sprintf("callback count: %d", count)
}

func TestCheckOnceMethodHEAD(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions([]string{srv.URL})
	opts.Method = "HEAD"
	CheckOnce(context.Background(), srv.URL, opts)
	if gotMethod != "HEAD" {
		t.Errorf("expected HEAD, got %s", gotMethod)
	}
}
