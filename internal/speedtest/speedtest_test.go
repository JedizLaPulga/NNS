package speedtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.DownloadURL == "" {
		t.Error("DefaultConfig().DownloadURL should not be empty")
	}
	if cfg.DownloadSize <= 0 {
		t.Error("DefaultConfig().DownloadSize should be positive")
	}
	if cfg.Timeout <= 0 {
		t.Error("DefaultConfig().Timeout should be positive")
	}
	if cfg.Connections <= 0 {
		t.Error("DefaultConfig().Connections should be positive")
	}
}

func TestNewTester(t *testing.T) {
	tests := []struct {
		name            string
		cfg             Config
		wantTimeout     time.Duration
		wantConnections int
	}{
		{
			name:            "defaults applied",
			cfg:             Config{},
			wantTimeout:     60 * time.Second,
			wantConnections: 4,
		},
		{
			name:            "custom values preserved",
			cfg:             Config{Timeout: 30 * time.Second, Connections: 8},
			wantTimeout:     30 * time.Second,
			wantConnections: 8,
		},
		{
			name:            "zero timeout gets default",
			cfg:             Config{Timeout: 0},
			wantTimeout:     60 * time.Second,
			wantConnections: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tester := NewTester(tt.cfg)
			if tester.cfg.Timeout != tt.wantTimeout {
				t.Errorf("Timeout = %v, want %v", tester.cfg.Timeout, tt.wantTimeout)
			}
			if tester.cfg.Connections != tt.wantConnections {
				t.Errorf("Connections = %d, want %d", tester.cfg.Connections, tt.wantConnections)
			}
			if tester.client == nil {
				t.Error("client should be initialized")
			}
		})
	}
}

func TestBytesToMbps(t *testing.T) {
	tests := []struct {
		bytes    int64
		duration time.Duration
		want     float64
		tol      float64
	}{
		{0, time.Second, 0, 0.01},
		{125000, time.Second, 1.0, 0.01},     // 125KB/s = 1 Mbps
		{1250000, time.Second, 10.0, 0.01},   // 1.25MB/s = 10 Mbps
		{12500000, time.Second, 100.0, 0.01}, // 12.5MB/s = 100 Mbps
		{125000, 0, 0, 0.01},                 // Zero duration
	}

	for _, tt := range tests {
		got := bytesToMbps(tt.bytes, tt.duration)
		diff := got - tt.want
		if diff < 0 {
			diff = -diff
		}
		if diff > tt.tol {
			t.Errorf("bytesToMbps(%d, %v) = %v, want %v", tt.bytes, tt.duration, got, tt.want)
		}
	}
}

func TestFormatSpeed(t *testing.T) {
	tests := []struct {
		mbps     float64
		contains string
	}{
		{1.5, "Mbps"},
		{100.5, "Mbps"},
		{999.9, "Mbps"},
		{1000, "Gbps"},
		{1500, "Gbps"},
	}

	for _, tt := range tests {
		got := FormatSpeed(tt.mbps)
		if !strings.Contains(got, tt.contains) {
			t.Errorf("FormatSpeed(%v) = %q, should contain %q", tt.mbps, got, tt.contains)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		contains string
	}{
		{500, "B"},
		{1024, "KB"},
		{1048576, "MB"},
		{1073741824, "GB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if !strings.Contains(got, tt.contains) {
			t.Errorf("FormatBytes(%d) = %q, should contain %q", tt.bytes, got, tt.contains)
		}
	}
}

func TestProgressReader(t *testing.T) {
	data := []byte("Hello, World!")
	reader := &progressReader{
		reader:   nopCloser{strings.NewReader(string(data))},
		total:    int64(len(data)),
		progress: func(p float64) {},
	}

	buf := make([]byte, 5)
	n, err := reader.Read(buf)
	if err != nil {
		t.Errorf("Read error: %v", err)
	}
	if n != 5 {
		t.Errorf("Read %d bytes, want 5", n)
	}
	if reader.read != 5 {
		t.Errorf("read counter = %d, want 5", reader.read)
	}
}

type nopCloser struct {
	*strings.Reader
}

func (nopCloser) Close() error { return nil }

func TestEstimateDuration(t *testing.T) {
	tests := []struct {
		mbps   float64
		sizeMB int64
		want   time.Duration
		tol    time.Duration
	}{
		{100, 10, 800 * time.Millisecond, 100 * time.Millisecond}, // 10MB at 100Mbps ≈ 0.8s
		{10, 10, 8 * time.Second, 1 * time.Second},                // 10MB at 10Mbps ≈ 8s
		{0, 10, 30 * time.Second, 0},                              // Zero speed = default
		{-10, 10, 30 * time.Second, 0},                            // Negative speed = default
	}

	for _, tt := range tests {
		got := EstimateDuration(tt.mbps, tt.sizeMB)
		diff := got - tt.want
		if diff < 0 {
			diff = -diff
		}
		if diff > tt.tol {
			t.Errorf("EstimateDuration(%v, %d) = %v, want %v", tt.mbps, tt.sizeMB, got, tt.want)
		}
	}
}

func TestBytesReaderAt(t *testing.T) {
	data := []byte("Hello, World!")
	reader := &bytesReaderAt{data: data}

	buf := make([]byte, 5)

	// Read from start
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Errorf("ReadAt(0) error: %v", err)
	}
	if n != 5 || string(buf) != "Hello" {
		t.Errorf("ReadAt(0) = %q, want 'Hello'", string(buf[:n]))
	}

	// Read from offset
	n, err = reader.ReadAt(buf, 7)
	if n != 5 || string(buf[:n]) != "World" {
		t.Errorf("ReadAt(7) = %q, want 'World'", string(buf[:n]))
	}

	// Read past end
	n, err = reader.ReadAt(buf, 100)
	if n != 0 {
		t.Errorf("ReadAt(100) n = %d, want 0", n)
	}
}

func TestDownloadWithMockServer(t *testing.T) {
	// Create a mock server
	data := strings.Repeat("X", 1024*10) // 10KB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "10240")
			return
		}
		w.Write([]byte(data))
	}))
	defer server.Close()

	cfg := Config{
		DownloadURL:  server.URL,
		DownloadSize: 10240,
		Timeout:      10 * time.Second,
		Connections:  1,
	}

	tester := NewTester(cfg)
	ctx := context.Background()

	speed, err := tester.TestDownloadOnly(ctx)
	if err != nil {
		t.Fatalf("TestDownloadOnly() error: %v", err)
	}

	if speed <= 0 {
		t.Error("Speed should be positive")
	}
}

func TestLatencyWithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		DownloadURL: server.URL,
		Timeout:     10 * time.Second,
	}

	tester := NewTester(cfg)
	ctx := context.Background()

	latency, err := tester.TestLatencyOnly(ctx)
	if err != nil {
		t.Fatalf("TestLatencyOnly() error: %v", err)
	}

	if latency <= 0 {
		t.Error("Latency should be positive")
	}
	if latency > 5*time.Second {
		t.Errorf("Latency too high for localhost: %v", latency)
	}
}

func TestRunWithCallback(t *testing.T) {
	data := strings.Repeat("X", 1024) // 1KB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "1024")
			return
		}
		w.Write([]byte(data))
	}))
	defer server.Close()

	cfg := Config{
		DownloadURL:  server.URL,
		DownloadSize: 1024,
		Timeout:      10 * time.Second,
	}

	tester := NewTester(cfg)
	ctx := context.Background()

	stages := make([]string, 0)
	result, err := tester.Run(ctx, func(stage string, progress float64) {
		stages = append(stages, stage)
	})

	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if result == nil {
		t.Fatal("Run() returned nil result")
	}

	// Should have latency and download stages
	hasLatency := false
	hasDownload := false
	hasComplete := false
	for _, s := range stages {
		if s == "latency" {
			hasLatency = true
		}
		if s == "download" {
			hasDownload = true
		}
		if s == "complete" {
			hasComplete = true
		}
	}

	if !hasLatency {
		t.Error("Missing 'latency' stage callback")
	}
	if !hasDownload {
		t.Error("Missing 'download' stage callback")
	}
	if !hasComplete {
		t.Error("Missing 'complete' stage callback")
	}
}

func TestContextCancellation(t *testing.T) {
	// Server that never responds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer server.Close()

	cfg := Config{
		DownloadURL: server.URL,
		Timeout:     5 * time.Second,
	}

	tester := NewTester(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := tester.Run(ctx, nil)
	elapsed := time.Since(start)

	// Should have exited quickly due to context timeout
	if elapsed > 2*time.Second {
		t.Errorf("Run() took %v, should have been cancelled sooner", elapsed)
	}

	// Error is expected
	if err == nil {
		t.Log("Expected error due to timeout/cancellation")
	}
}

func TestQuickTest(t *testing.T) {
	data := strings.Repeat("X", 1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "1024")
			return
		}
		w.Write([]byte(data))
	}))
	defer server.Close()

	ctx := context.Background()
	result, err := QuickTest(ctx, server.URL)

	if err != nil {
		t.Fatalf("QuickTest() error: %v", err)
	}

	if result.DownloadSpeed <= 0 {
		t.Error("DownloadSpeed should be positive")
	}

	if result.DownloadBytes != 1024 {
		t.Errorf("DownloadBytes = %d, want 1024", result.DownloadBytes)
	}
}
