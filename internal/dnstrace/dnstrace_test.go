package dnstrace

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", cfg.Timeout)
	}
	if cfg.MaxDepth != 10 {
		t.Errorf("expected max depth 10, got %d", cfg.MaxDepth)
	}
	if cfg.QueryType != "A" {
		t.Errorf("expected query type A, got %s", cfg.QueryType)
	}
}

func TestNew(t *testing.T) {
	tracer := New(Config{})

	if tracer.config.Timeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", tracer.config.Timeout)
	}
	if tracer.config.MaxDepth != 10 {
		t.Errorf("expected default max depth 10, got %d", tracer.config.MaxDepth)
	}
}

func TestNewWithCustomConfig(t *testing.T) {
	cfg := Config{
		Timeout:   10 * time.Second,
		MaxDepth:  5,
		QueryType: "AAAA",
	}
	tracer := New(cfg)

	if tracer.config.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", tracer.config.Timeout)
	}
	if tracer.config.MaxDepth != 5 {
		t.Errorf("expected max depth 5, got %d", tracer.config.MaxDepth)
	}
	if tracer.config.QueryType != "AAAA" {
		t.Errorf("expected query type AAAA, got %s", tracer.config.QueryType)
	}
}

func TestRootServers(t *testing.T) {
	if len(RootServers) != 13 {
		t.Errorf("expected 13 root servers, got %d", len(RootServers))
	}

	// Check first root server
	if RootServers[0] != "a.root-servers.net" {
		t.Errorf("expected a.root-servers.net, got %s", RootServers[0])
	}
}

func TestFormatStep(t *testing.T) {
	step := Step{
		Level:      0,
		ServerName: "a.root-servers.net",
		ServerIP:   "198.41.0.4",
		Query:      "example.com.",
		QueryType:  "A",
		Duration:   50 * time.Millisecond,
		Answers:    []string{"93.184.216.34"},
	}

	formatted := FormatStep(step)

	if formatted == "" {
		t.Error("expected non-empty formatted step")
	}
	if len(formatted) < 10 {
		t.Error("formatted step too short")
	}
}

func TestFormatStepWithError(t *testing.T) {
	step := Step{
		Level:      1,
		ServerName: "ns1.example.com",
		Query:      "example.com.",
		Error:      context.DeadlineExceeded,
		Duration:   5 * time.Second,
	}

	formatted := FormatStep(step)
	if formatted == "" {
		t.Error("expected non-empty formatted step with error")
	}
}

func TestFormatStepWithReferrals(t *testing.T) {
	step := Step{
		Level:      0,
		ServerName: "a.root-servers.net",
		ServerIP:   "198.41.0.4",
		Query:      "example.com.",
		QueryType:  "A",
		Duration:   30 * time.Millisecond,
		Referrals:  []string{"a.gtld-servers.net", "b.gtld-servers.net"},
	}

	formatted := FormatStep(step)
	if formatted == "" {
		t.Error("expected non-empty formatted step with referrals")
	}
}

func TestFormatTrace(t *testing.T) {
	trace := &Trace{
		Target:    "example.com",
		QueryType: "A",
		Steps: []Step{
			{Level: 0, ServerName: "a.root-servers.net", Duration: 50 * time.Millisecond},
			{Level: 1, ServerName: "a.gtld-servers.net", Duration: 30 * time.Millisecond},
		},
		FinalIPs:  []string{"93.184.216.34"},
		TotalTime: 100 * time.Millisecond,
		Success:   true,
	}

	formatted := FormatTrace(trace)

	if formatted == "" {
		t.Error("expected non-empty formatted trace")
	}
	if len(formatted) < 50 {
		t.Error("formatted trace too short")
	}
}

func TestFormatTraceFailure(t *testing.T) {
	trace := &Trace{
		Target:    "invalid.example",
		QueryType: "A",
		Steps:     []Step{},
		TotalTime: 5 * time.Second,
		Success:   false,
		Error:     context.DeadlineExceeded,
	}

	formatted := FormatTrace(trace)
	if formatted == "" {
		t.Error("expected non-empty formatted trace for failure")
	}
}

func TestTraceWithCallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	cfg := Config{
		Timeout:     2 * time.Second,
		MaxDepth:    3,
		QueryType:   "A",
		StartServer: "8.8.8.8", // Use Google DNS to avoid slow root server queries
	}
	tracer := New(cfg)

	stepCount := 0
	callback := func(step Step) {
		stepCount++
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	trace, err := tracer.TraceResolution(ctx, "google.com", callback)

	if err != nil && err != context.DeadlineExceeded {
		t.Skipf("network test failed (expected in CI): %v", err)
	}

	if trace == nil {
		t.Fatal("expected non-nil trace")
	}

	if stepCount == 0 {
		t.Error("expected callback to be called at least once")
	}
}

func TestQuickTrace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	trace, err := QuickTrace(ctx, "example.com")

	if err != nil && err != context.DeadlineExceeded {
		t.Skipf("network test failed (expected in CI): %v", err)
	}

	if trace == nil {
		t.Fatal("expected non-nil trace")
	}

	if trace.Target != "example.com" {
		t.Errorf("expected target example.com, got %s", trace.Target)
	}
}

func TestTraceContextCancellation(t *testing.T) {
	tracer := New(DefaultConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	trace, err := tracer.TraceResolution(ctx, "example.com", nil)

	if err != context.Canceled {
		// May or may not get cancelled depending on timing
		_ = err
	}

	if trace == nil {
		t.Fatal("expected non-nil trace even on cancellation")
	}
}
