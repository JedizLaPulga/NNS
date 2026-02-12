package reverseproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.ListenAddr != ":8080" {
		t.Errorf("expected :8080, got %s", opts.ListenAddr)
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", opts.Timeout)
	}
	if !opts.LogRequests {
		t.Error("expected LogRequests to be true by default")
	}
}

func TestNewProxyValidation(t *testing.T) {
	_, err := NewProxy(Options{})
	if err == nil {
		t.Error("expected error for empty backend URL")
	}

	_, err = NewProxy(Options{BackendURL: "://bad"})
	if err == nil {
		t.Error("expected error for invalid backend URL")
	}

	_, err = NewProxy(Options{BackendURL: "noscheme"})
	if err == nil {
		t.Error("expected error for URL without scheme")
	}

	p, err := NewProxy(Options{BackendURL: "http://localhost:3000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ListenAddr() != ":8080" {
		t.Errorf("expected default listen addr :8080, got %s", p.ListenAddr())
	}
	if p.BackendURL().Host != "localhost:3000" {
		t.Errorf("expected backend host localhost:3000, got %s", p.BackendURL().Host)
	}
}

func TestNewStatistics(t *testing.T) {
	stats := NewStatistics()
	if stats.TotalReqs != 0 {
		t.Errorf("expected 0 total reqs, got %d", stats.TotalReqs)
	}
	if stats.StatusCounts == nil {
		t.Error("expected StatusCounts to be initialized")
	}
	if stats.MethodCounts == nil {
		t.Error("expected MethodCounts to be initialized")
	}
}

func TestStatisticsRecord(t *testing.T) {
	stats := NewStatistics()

	stats.Record(RequestLog{
		Method:     "GET",
		StatusCode: 200,
		Latency:    10 * time.Millisecond,
		BytesSent:  100,
	})
	stats.Record(RequestLog{
		Method:     "POST",
		StatusCode: 201,
		Latency:    20 * time.Millisecond,
		BytesSent:  200,
	})
	stats.Record(RequestLog{
		Method: "GET",
		Error:  fmt.Errorf("connection refused"),
	})

	if stats.TotalReqs != 3 {
		t.Errorf("expected 3 total, got %d", stats.TotalReqs)
	}
	if stats.SuccessReqs != 2 {
		t.Errorf("expected 2 success, got %d", stats.SuccessReqs)
	}
	if stats.FailedReqs != 1 {
		t.Errorf("expected 1 failed, got %d", stats.FailedReqs)
	}
	if stats.BytesSent != 300 {
		t.Errorf("expected 300 bytes, got %d", stats.BytesSent)
	}
	if stats.MinLatency != 10*time.Millisecond {
		t.Errorf("expected min 10ms, got %v", stats.MinLatency)
	}
	if stats.MaxLatency != 20*time.Millisecond {
		t.Errorf("expected max 20ms, got %v", stats.MaxLatency)
	}
	if stats.StatusCounts[200] != 1 {
		t.Errorf("expected 200 count 1, got %d", stats.StatusCounts[200])
	}
	if stats.MethodCounts["GET"] != 2 {
		t.Errorf("expected GET count 2, got %d", stats.MethodCounts["GET"])
	}
}

func TestStatisticsCalculate(t *testing.T) {
	stats := NewStatistics()
	stats.Record(RequestLog{Method: "GET", StatusCode: 200, Latency: 10 * time.Millisecond})
	stats.Record(RequestLog{Method: "GET", StatusCode: 200, Latency: 20 * time.Millisecond})
	stats.Record(RequestLog{Method: "GET", StatusCode: 200, Latency: 30 * time.Millisecond})

	stats.Calculate()

	if stats.AvgLatency != 20*time.Millisecond {
		t.Errorf("expected avg 20ms, got %v", stats.AvgLatency)
	}
	if stats.MedianLat != 20*time.Millisecond {
		t.Errorf("expected median 20ms, got %v", stats.MedianLat)
	}
	if stats.P95Latency <= 0 {
		t.Error("expected positive P95")
	}
}

func TestStatisticsCalculateEmpty(t *testing.T) {
	stats := NewStatistics()
	stats.Calculate()
	if stats.AvgLatency != 0 {
		t.Errorf("expected 0 avg for empty, got %v", stats.AvgLatency)
	}
}

func TestStatisticsSnapshot(t *testing.T) {
	stats := NewStatistics()
	stats.Record(RequestLog{Method: "GET", StatusCode: 200, Latency: 10 * time.Millisecond})

	snap := stats.Snapshot()
	if snap.TotalReqs != 1 {
		t.Errorf("expected snapshot total 1, got %d", snap.TotalReqs)
	}

	// Mutating original should not affect snapshot
	stats.Record(RequestLog{Method: "POST", StatusCode: 200, Latency: 20 * time.Millisecond})
	if snap.TotalReqs != 1 {
		t.Error("snapshot was mutated")
	}
}

func TestStatisticsFormat(t *testing.T) {
	stats := NewStatistics()
	stats.Record(RequestLog{Method: "GET", StatusCode: 200, Latency: 10 * time.Millisecond, BytesSent: 1024})
	stats.Record(RequestLog{Method: "POST", StatusCode: 201, Latency: 20 * time.Millisecond, BytesSent: 2048})

	output := stats.Format()

	if !strings.Contains(output, "REVERSE PROXY STATISTICS") {
		t.Error("format should contain header")
	}
	if !strings.Contains(output, "Requests:") {
		t.Error("format should contain request count")
	}
	if !strings.Contains(output, "Latency:") {
		t.Error("format should contain latency section")
	}
	if !strings.Contains(output, "200") {
		t.Error("format should contain status code 200")
	}
	if !strings.Contains(output, "GET") {
		t.Error("format should contain GET method")
	}
}

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"/api", "/v1", "/api/v1"},
		{"/api/", "/v1", "/api/v1"},
		{"/api", "v1", "/api/v1"},
		{"/api/", "v1", "/api/v1"},
		{"", "/path", "/path"},
	}

	for _, tt := range tests {
		got := singleJoiningSlash(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestHeaderRules(t *testing.T) {
	rules := []HeaderRule{
		{Name: "X-Custom", Value: "test-value"},
		{Name: "X-Remove", Remove: true},
	}

	if rules[0].Remove {
		t.Error("first rule should not be remove")
	}
	if !rules[1].Remove {
		t.Error("second rule should be remove")
	}
	if rules[0].Value != "test-value" {
		t.Errorf("expected test-value, got %s", rules[0].Value)
	}
}

// TestProxyIntegration tests the full proxy lifecycle with a local backend.
func TestProxyIntegration(t *testing.T) {
	// Start a backend server
	backend := http.NewServeMux()
	backend.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	})
	backend.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "method=%s xff=%s", r.Method, r.Header.Get("X-Forwarded-For"))
	})

	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start backend: %v", err)
	}
	defer backendListener.Close()

	backendServer := &http.Server{Handler: backend}
	go backendServer.Serve(backendListener)
	defer backendServer.Close()

	backendPort := backendListener.Addr().(*net.TCPAddr).Port
	backendURL := fmt.Sprintf("http://127.0.0.1:%d", backendPort)

	// Start proxy
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get proxy port: %v", err)
	}
	proxyAddr := proxyListener.Addr().String()
	proxyListener.Close()

	var loggedReqs []RequestLog
	var logMu sync.Mutex

	proxy, err := NewProxy(Options{
		ListenAddr:  proxyAddr,
		BackendURL:  backendURL,
		Timeout:     5 * time.Second,
		LogRequests: true,
		Headers: []HeaderRule{
			{Name: "X-Proxy-By", Value: "nns"},
		},
		OnRequest: func(log RequestLog) {
			logMu.Lock()
			loggedReqs = append(loggedReqs, log)
			logMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go proxy.Run(ctx)
	time.Sleep(100 * time.Millisecond) // Let proxy start

	client := &http.Client{Timeout: 5 * time.Second}

	// Test health endpoint
	resp, err := client.Get(fmt.Sprintf("http://%s/health", proxyAddr))
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Test echo endpoint
	resp, err = client.Get(fmt.Sprintf("http://%s/echo", proxyAddr))
	if err != nil {
		t.Fatalf("GET /echo failed: %v", err)
	}
	resp.Body.Close()

	time.Sleep(50 * time.Millisecond)

	// Verify stats
	if proxy.Stats.TotalReqs != 2 {
		t.Errorf("expected 2 total reqs, got %d", proxy.Stats.TotalReqs)
	}
	if proxy.Stats.SuccessReqs != 2 {
		t.Errorf("expected 2 success reqs, got %d", proxy.Stats.SuccessReqs)
	}

	// Verify request logging
	logMu.Lock()
	if len(loggedReqs) != 2 {
		t.Errorf("expected 2 logged requests, got %d", len(loggedReqs))
	}
	logMu.Unlock()

	// Cancel and verify clean shutdown
	cancel()
	time.Sleep(100 * time.Millisecond)
}

func TestStatusRecorder(t *testing.T) {
	rec := &statusRecorder{
		ResponseWriter: &mockResponseWriter{},
		statusCode:     200,
	}

	rec.WriteHeader(404)
	if rec.statusCode != 404 {
		t.Errorf("expected 404, got %d", rec.statusCode)
	}

	n, err := rec.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}
	if rec.bytes != 5 {
		t.Errorf("expected 5 bytes tracked, got %d", rec.bytes)
	}
}

type mockResponseWriter struct {
	headers http.Header
}

func (m *mockResponseWriter) Header() http.Header {
	if m.headers == nil {
		m.headers = make(http.Header)
	}
	return m.headers
}
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) WriteHeader(int)             {}
