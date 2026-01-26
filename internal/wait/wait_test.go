package wait

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input   string
		want    Target
		wantErr bool
	}{
		{"localhost:8080", Target{Host: "localhost", Port: 8080, Protocol: TCP}, false},
		{"192.168.1.1:22", Target{Host: "192.168.1.1", Port: 22, Protocol: TCP}, false},
		{"[::1]:443", Target{Host: "::1", Port: 443, Protocol: TCP}, false},
		{"invalid", Target{}, true},
		{"host:-1", Target{}, true},
		{"host:99999", Target{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseTarget(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTarget(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Host != tt.want.Host || got.Port != tt.want.Port {
					t.Errorf("ParseTarget(%q) = %+v, want %+v", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestTargetAddress(t *testing.T) {
	target := Target{Host: "localhost", Port: 8080}
	if got := target.Address(); got != "localhost:8080" {
		t.Errorf("Address() = %q, want %q", got, "localhost:8080")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, 60*time.Second)
	}
	if cfg.Interval != time.Second {
		t.Errorf("Interval = %v, want %v", cfg.Interval, time.Second)
	}
}

func TestWaitSuccess(t *testing.T) {
	// Start a test server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	cfg := Config{
		Timeout:  5 * time.Second,
		Interval: 100 * time.Millisecond,
	}
	w := New(cfg)

	target := Target{Host: "127.0.0.1", Port: port, Protocol: TCP}
	result := w.Wait(context.Background(), target)

	if !result.Success {
		t.Errorf("Wait failed: %v", result.Error)
	}
	if result.Attempts < 1 {
		t.Errorf("Attempts = %d, want >= 1", result.Attempts)
	}
}

func TestWaitTimeout(t *testing.T) {
	cfg := Config{
		Timeout:  500 * time.Millisecond,
		Interval: 100 * time.Millisecond,
	}
	w := New(cfg)

	// Use a port that's very unlikely to be open
	target := Target{Host: "127.0.0.1", Port: 59999, Protocol: TCP}
	result := w.Wait(context.Background(), target)

	if result.Success {
		t.Error("Wait should have failed (timeout)")
	}
	if result.Error == nil {
		t.Error("Error should not be nil on timeout")
	}
}

func TestWaitContextCancel(t *testing.T) {
	cfg := Config{
		Timeout:  30 * time.Second,
		Interval: 100 * time.Millisecond,
	}
	w := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	target := Target{Host: "127.0.0.1", Port: 59999, Protocol: TCP}
	result := w.Wait(ctx, target)

	if result.Success {
		t.Error("Wait should have failed (context cancelled)")
	}
}

func TestWaitProgress(t *testing.T) {
	cfg := Config{
		Timeout:  500 * time.Millisecond,
		Interval: 100 * time.Millisecond,
	}
	w := New(cfg)

	progressCalled := 0
	w.SetProgressFunc(func(attempt int, elapsed time.Duration, err error) {
		progressCalled++
	})

	target := Target{Host: "127.0.0.1", Port: 59999, Protocol: TCP}
	_ = w.Wait(context.Background(), target)

	if progressCalled == 0 {
		t.Error("Progress callback was never called")
	}
}

func TestWaitMultiple(t *testing.T) {
	// Start two test servers
	ln1, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln1.Close()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln2.Close()

	_, p1, _ := net.SplitHostPort(ln1.Addr().String())
	_, p2, _ := net.SplitHostPort(ln2.Addr().String())
	var port1, port2 int
	fmt.Sscanf(p1, "%d", &port1)
	fmt.Sscanf(p2, "%d", &port2)

	cfg := Config{
		Timeout:  5 * time.Second,
		Interval: 100 * time.Millisecond,
	}
	w := New(cfg)

	targets := []Target{
		{Host: "127.0.0.1", Port: port1, Protocol: TCP},
		{Host: "127.0.0.1", Port: port2, Protocol: TCP},
	}

	results := w.WaitMultiple(context.Background(), targets)

	for i, r := range results {
		if !r.Success {
			t.Errorf("Target %d failed: %v", i, r.Error)
		}
	}
}

func TestWaitAny(t *testing.T) {
	// Start one test server
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	cfg := Config{
		Timeout:  5 * time.Second,
		Interval: 100 * time.Millisecond,
	}
	w := New(cfg)

	targets := []Target{
		{Host: "127.0.0.1", Port: 59999, Protocol: TCP}, // Not available
		{Host: "127.0.0.1", Port: port, Protocol: TCP},  // Available
	}

	result := w.WaitAny(context.Background(), targets)

	if !result.Success {
		t.Errorf("WaitAny failed: %v", result.Error)
	}
	if result.Target.Port != port {
		t.Errorf("WaitAny returned wrong target: got port %d, want %d", result.Target.Port, port)
	}
}

func TestFormatResult(t *testing.T) {
	successResult := Result{
		Target:   Target{Host: "localhost", Port: 8080},
		Success:  true,
		Duration: 2 * time.Second,
		Attempts: 3,
	}

	got := FormatResult(successResult)
	if got == "" {
		t.Error("FormatResult returned empty string")
	}

	failResult := Result{
		Target:   Target{Host: "localhost", Port: 8080},
		Success:  false,
		Duration: 5 * time.Second,
		Attempts: 5,
		Error:    net.ErrClosed,
	}

	got = FormatResult(failResult)
	if got == "" {
		t.Error("FormatResult returned empty string for failure")
	}
}
