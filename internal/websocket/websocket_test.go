package websocket

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestNewTester(t *testing.T) {
	tester := NewTester("ws://example.com/socket")

	if tester.URL != "ws://example.com/socket" {
		t.Errorf("expected URL 'ws://example.com/socket', got '%s'", tester.URL)
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
	if tester.MessageSize != 32 {
		t.Errorf("expected default message size 32, got %d", tester.MessageSize)
	}
	if tester.Stats == nil {
		t.Error("expected Stats to be initialized")
	}
}

func TestNewTesterWSS(t *testing.T) {
	tester := NewTester("wss://secure.example.com/socket")

	if !strings.HasPrefix(tester.Origin, "https://") {
		t.Errorf("expected https origin for wss URL, got '%s'", tester.Origin)
	}
}

func TestStatistics(t *testing.T) {
	stats := NewStatistics()

	// Add successful results
	stats.Add(Result{Seq: 1, Success: true, RoundTripTime: 10 * time.Millisecond})
	stats.Add(Result{Seq: 2, Success: true, RoundTripTime: 20 * time.Millisecond})
	stats.Add(Result{Seq: 3, Success: true, RoundTripTime: 15 * time.Millisecond})
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
	if stats.MinRTT != 10*time.Millisecond {
		t.Errorf("expected MinRTT=10ms, got %v", stats.MinRTT)
	}
	if stats.MaxRTT != 20*time.Millisecond {
		t.Errorf("expected MaxRTT=20ms, got %v", stats.MaxRTT)
	}
}

func TestQuality(t *testing.T) {
	tests := []struct {
		name       string
		successful int
		avgRTT     time.Duration
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
			stats.AvgRTT = tt.avgRTT

			quality := stats.Quality()
			if len(quality) == 0 {
				t.Error("expected non-empty quality string")
			}
			emoji := []rune(quality)[0]
			expectedEmoji := []rune(tt.wantPrefix)[0]
			if emoji != expectedEmoji {
				t.Errorf("expected quality starting with %s, got %s", tt.wantPrefix, quality)
			}
		})
	}
}

func TestSupportedProtocols(t *testing.T) {
	protocols := SupportedProtocols()
	if len(protocols) == 0 {
		t.Error("expected at least one supported protocol")
	}
}

func TestStatisticsCalculateEmpty(t *testing.T) {
	stats := NewStatistics()
	stats.Calculate() // Should not panic

	if stats.Sent != 0 {
		t.Errorf("expected Sent=0, got %d", stats.Sent)
	}
}

func TestStatisticsJitter(t *testing.T) {
	stats := NewStatistics()
	stats.Add(Result{Seq: 1, Success: true, RoundTripTime: 10 * time.Millisecond})
	stats.Add(Result{Seq: 2, Success: true, RoundTripTime: 20 * time.Millisecond})
	stats.Add(Result{Seq: 3, Success: true, RoundTripTime: 15 * time.Millisecond})

	stats.Calculate()

	// Jitter should be calculated
	if stats.Jitter == 0 {
		t.Error("expected non-zero jitter")
	}
}

// TestRunWithEchoServer tests the WebSocket tester against a local echo server.
func TestRunWithEchoServer(t *testing.T) {
	// Create a test WebSocket echo server
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var msg string
		for {
			err := websocket.Message.Receive(ws, &msg)
			if err != nil {
				return
			}
			websocket.Message.Send(ws, msg)
		}
	}))
	defer server.Close()

	// Convert http:// to ws://
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/"

	tester := NewTester(wsURL)
	tester.Count = 3
	tester.Interval = 100 * time.Millisecond
	tester.Timeout = 5 * time.Second

	var results []Result
	err := tester.Run(context.Background(), func(r Result) {
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
		// RTT can be 0 on very fast localhost tests, so just check it's non-negative
		if r.RoundTripTime < 0 {
			t.Errorf("result %d should have non-negative RTT", i+1)
		}
	}

	if tester.Stats.Successful != 3 {
		t.Errorf("expected 3 successful, got %d", tester.Stats.Successful)
	}
}

// TestRunContextCancellation tests context cancellation.
func TestRunContextCancellation(t *testing.T) {
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var msg string
		for {
			err := websocket.Message.Receive(ws, &msg)
			if err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			websocket.Message.Send(ws, msg)
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/"

	tester := NewTester(wsURL)
	tester.Count = 100
	tester.Interval = 500 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var count int
	_ = tester.Run(ctx, func(r Result) {
		count++
	})

	if count >= 100 {
		t.Error("context cancellation did not work")
	}
}

func TestResultError(t *testing.T) {
	tester := NewTester("ws://invalid-host-that-does-not-exist.local:12345/")
	tester.Count = 1
	tester.Timeout = 1 * time.Second

	var results []Result
	_ = tester.Run(context.Background(), func(r Result) {
		results = append(results, r)
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Success {
		t.Error("expected connection to fail")
	}
	if results[0].Error == nil {
		t.Error("expected error to be set")
	}
}
