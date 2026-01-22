package tcptest

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewTester(t *testing.T) {
	tester := NewTester("example.com", 80)

	if tester.Host != "example.com" {
		t.Errorf("expected host 'example.com', got '%s'", tester.Host)
	}
	if tester.Port != 80 {
		t.Errorf("expected port 80, got %d", tester.Port)
	}
	if tester.Count != 4 {
		t.Errorf("expected default count 4, got %d", tester.Count)
	}
	if tester.Interval != 1*time.Second {
		t.Errorf("expected default interval 1s, got %v", tester.Interval)
	}
	if tester.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", tester.Timeout)
	}
	if tester.UseTLS {
		t.Error("expected UseTLS to be false by default")
	}
	if tester.Stats == nil {
		t.Error("expected Stats to be initialized")
	}
}

func TestAddress(t *testing.T) {
	tester := NewTester("example.com", 443)
	addr := tester.Address()
	expected := "example.com:443"
	if addr != expected {
		t.Errorf("expected '%s', got '%s'", expected, addr)
	}
}

func TestStatistics(t *testing.T) {
	stats := NewStatistics()

	// Add successful results
	stats.Add(Result{Seq: 1, Success: true, TotalTime: 10 * time.Millisecond, ConnectTime: 5 * time.Millisecond, DNSTime: 2 * time.Millisecond})
	stats.Add(Result{Seq: 2, Success: true, TotalTime: 20 * time.Millisecond, ConnectTime: 8 * time.Millisecond, DNSTime: 3 * time.Millisecond})
	stats.Add(Result{Seq: 3, Success: true, TotalTime: 15 * time.Millisecond, ConnectTime: 6 * time.Millisecond, DNSTime: 2 * time.Millisecond})
	stats.Add(Result{Seq: 4, Success: false})

	stats.Calculate()

	if stats.Sent != 4 {
		t.Errorf("expected Sent=4, got %d", stats.Sent)
	}
	if stats.Successful != 3 {
		t.Errorf("expected Successful=3, got %d", stats.Successful)
	}
	if stats.Failed != 1 {
		t.Errorf("expected Failed=1, got %d", stats.Failed)
	}
	if stats.SuccessRate != 75.0 {
		t.Errorf("expected SuccessRate=75.0, got %.2f", stats.SuccessRate)
	}
	if stats.MinTime != 10*time.Millisecond {
		t.Errorf("expected MinTime=10ms, got %v", stats.MinTime)
	}
	if stats.MaxTime != 20*time.Millisecond {
		t.Errorf("expected MaxTime=20ms, got %v", stats.MaxTime)
	}
}

func TestQuality(t *testing.T) {
	tests := []struct {
		name       string
		successful int
		avgTime    time.Duration
		wantPrefix string
	}{
		{"no connection", 0, 0, "❌"},
		{"excellent", 4, 30 * time.Millisecond, "🟢"},
		{"good", 4, 80 * time.Millisecond, "🟢"},
		{"fair", 4, 150 * time.Millisecond, "🟡"},
		{"slow", 4, 300 * time.Millisecond, "🟠"},
		{"poor", 4, 600 * time.Millisecond, "🔴"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := NewStatistics()
			stats.Successful = tt.successful
			stats.Sent = 4
			stats.SuccessRate = float64(tt.successful) / 4.0 * 100
			stats.AvgTime = tt.avgTime

			quality := stats.Quality()
			if len(quality) == 0 {
				t.Error("expected non-empty quality string")
			}
			// Check emoji prefix
			emoji := []rune(quality)[0]
			expectedEmoji := []rune(tt.wantPrefix)[0]
			if emoji != expectedEmoji {
				t.Errorf("expected quality starting with %s, got %s", tt.wantPrefix, quality)
			}
		})
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0000, "Unknown (0x0000)"},
	}

	for _, tt := range tests {
		result := tlsVersionString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionString(0x%04x) = %s, want %s", tt.version, result, tt.expected)
		}
	}
}

// TestRunWithLocalServer tests the Run function with a local TCP server.
func TestRunWithLocalServer(t *testing.T) {
	// Start a local TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer listener.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Get the port
	addr := listener.Addr().(*net.TCPAddr)

	// Create tester
	tester := NewTester("127.0.0.1", addr.Port)
	tester.Count = 3
	tester.Interval = 100 * time.Millisecond
	tester.Timeout = 2 * time.Second

	var results []Result
	err = tester.Run(context.Background(), func(r Result) {
		results = append(results, r)
	})

	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	for i, r := range results {
		if !r.Success {
			t.Errorf("result %d should be successful, got error: %v", i+1, r.Error)
		}
		if r.ConnectTime <= 0 {
			t.Errorf("result %d should have positive connect time", i+1)
		}
	}

	if tester.Stats.Successful != 3 {
		t.Errorf("expected 3 successful, got %d", tester.Stats.Successful)
	}
}

// TestRunContextCancellation tests that Run respects context cancellation.
func TestRunContextCancellation(t *testing.T) {
	// Start a local TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)

	tester := NewTester("127.0.0.1", addr.Port)
	tester.Count = 100 // Large count
	tester.Interval = 500 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var count int
	_ = tester.Run(ctx, func(r Result) {
		count++
	})

	// Should have been cancelled before completing all 100
	if count >= 100 {
		t.Error("context cancellation did not work, all 100 tests completed")
	}
}
