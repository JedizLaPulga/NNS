package portknock

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Delay != 500*time.Millisecond {
		t.Errorf("expected delay 500ms, got %v", opts.Delay)
	}
	if opts.Timeout != 2*time.Second {
		t.Errorf("expected timeout 2s, got %v", opts.Timeout)
	}
	if opts.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", opts.Protocol)
	}
}

func TestKnockEmptyHost(t *testing.T) {
	opts := DefaultOptions()
	opts.Ports = []int{1234}

	_, err := Knock(context.Background(), opts)
	if err == nil {
		t.Error("expected error for empty host")
	}
}

func TestKnockEmptyPorts(t *testing.T) {
	opts := DefaultOptions()
	opts.Host = "127.0.0.1"

	_, err := Knock(context.Background(), opts)
	if err == nil {
		t.Error("expected error for empty ports")
	}
}

func TestKnockLocalTCP(t *testing.T) {
	// Start a listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	opts := Options{
		Host:     "127.0.0.1",
		Ports:    []int{port},
		Delay:    50 * time.Millisecond,
		Timeout:  2 * time.Second,
		Protocol: "tcp",
	}

	result, err := Knock(context.Background(), opts)
	if err != nil {
		t.Fatalf("Knock failed: %v", err)
	}

	if len(result.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Results))
	}

	if !result.Results[0].Success {
		t.Error("expected knock to succeed")
	}

	if result.Results[0].State != "open" {
		t.Errorf("expected state 'open', got %q", result.Results[0].State)
	}
}

func TestKnockClosedPort(t *testing.T) {
	// Get a port that's not listening
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	opts := Options{
		Host:     "127.0.0.1",
		Ports:    []int{port},
		Delay:    50 * time.Millisecond,
		Timeout:  1 * time.Second,
		Protocol: "tcp",
	}

	result, err := Knock(context.Background(), opts)
	if err != nil {
		t.Fatalf("Knock failed: %v", err)
	}

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}

	// Knock still counts as "sent" even to a closed port
	if !result.Results[0].Success {
		t.Error("expected success=true (knock sent)")
	}

	if result.Results[0].State != "closed" {
		t.Errorf("expected state 'closed', got %q", result.Results[0].State)
	}
}

func TestKnockSequence(t *testing.T) {
	listeners := make([]net.Listener, 3)
	ports := make([]int, 3)

	for i := 0; i < 3; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		listeners[i] = l
		ports[i] = l.Addr().(*net.TCPAddr).Port

		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}(l)
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	opts := Options{
		Host:     "127.0.0.1",
		Ports:    ports,
		Delay:    50 * time.Millisecond,
		Timeout:  2 * time.Second,
		Protocol: "tcp",
	}

	result, err := Knock(context.Background(), opts)
	if err != nil {
		t.Fatalf("Knock failed: %v", err)
	}

	if len(result.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(result.Results))
	}

	for i, kr := range result.Results {
		if !kr.Success {
			t.Errorf("knock %d should have succeeded", i+1)
		}
		if kr.Seq != i+1 {
			t.Errorf("knock %d seq=%d, expected %d", i, kr.Seq, i+1)
		}
	}
}

func TestKnockWithVerify(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	opts := Options{
		Host:     "127.0.0.1",
		Ports:    []int{port},
		Delay:    50 * time.Millisecond,
		Timeout:  2 * time.Second,
		Protocol: "tcp",
		Verify:   port,
	}

	result, err := Knock(context.Background(), opts)
	if err != nil {
		t.Fatalf("Knock failed: %v", err)
	}

	if result.VerifyPort != port {
		t.Errorf("expected verify port %d, got %d", port, result.VerifyPort)
	}

	if result.VerifyState != "open" {
		t.Errorf("expected verify state 'open', got %q", result.VerifyState)
	}
}

func TestKnockContextCancellation(t *testing.T) {
	opts := Options{
		Host:     "127.0.0.1",
		Ports:    []int{1111, 2222, 3333, 4444, 5555},
		Delay:    500 * time.Millisecond,
		Timeout:  2 * time.Second,
		Protocol: "tcp",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result, _ := Knock(ctx, opts)

	if len(result.Results) >= 5 {
		t.Error("context cancellation should have stopped the sequence early")
	}
}

func TestFormatResult(t *testing.T) {
	result := &SequenceResult{
		Host:  "192.168.1.1",
		Ports: []int{1000, 2000, 3000},
		Results: []KnockResult{
			{Port: 1000, Seq: 1, Success: true, State: "closed", Duration: 5 * time.Millisecond},
			{Port: 2000, Seq: 2, Success: true, State: "closed", Duration: 3 * time.Millisecond},
			{Port: 3000, Seq: 3, Success: true, State: "closed", Duration: 4 * time.Millisecond},
		},
		Duration: 500 * time.Millisecond,
	}

	output := FormatResult(result)

	checks := []string{"192.168.1.1", "1000", "2000", "3000", "closed"}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("format output should contain %q", check)
		}
	}
}

func TestFormatResultWithVerify(t *testing.T) {
	result := &SequenceResult{
		Host:        "192.168.1.1",
		Ports:       []int{1000},
		Results:     []KnockResult{{Port: 1000, Seq: 1, Success: true, State: "closed"}},
		VerifyPort:  22,
		VerifyState: "open",
		Duration:    100 * time.Millisecond,
	}

	output := FormatResult(result)
	if !strings.Contains(output, "OPEN") {
		t.Error("format output should contain verification result")
	}
}

func TestFormatPorts(t *testing.T) {
	result := formatPorts([]int{100, 200, 300})
	if result != "100 → 200 → 300" {
		t.Errorf("expected '100 → 200 → 300', got %q", result)
	}
}

func TestVerifyIcon(t *testing.T) {
	tests := []struct {
		state string
		want  string
	}{
		{"open", "🟢"},
		{"closed", "🔴"},
		{"filtered", "🟡"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		result := verifyIcon(tt.state)
		if !strings.Contains(result, tt.want) {
			t.Errorf("verifyIcon(%q) should contain %q, got %q", tt.state, tt.want, result)
		}
	}
}

func TestIsTimeout(t *testing.T) {
	if isTimeout(fmt.Errorf("random error")) {
		t.Error("non-timeout error should return false")
	}
}

func TestIsConnectionRefused(t *testing.T) {
	if !isConnectionRefused(fmt.Errorf("connection refused")) {
		t.Error("should detect 'connection refused'")
	}
	if isConnectionRefused(fmt.Errorf("some other error")) {
		t.Error("should not match non-refused error")
	}
}

func TestProbePortClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	state := probePort("127.0.0.1", port, "tcp", 1*time.Second)
	if state != "closed" {
		t.Errorf("expected 'closed', got %q", state)
	}
}

func TestProbePortOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	state := probePort("127.0.0.1", port, "tcp", 1*time.Second)
	if state != "open" {
		t.Errorf("expected 'open', got %q", state)
	}
}
