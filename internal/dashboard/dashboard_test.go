package dashboard

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.RefreshInterval != time.Second {
		t.Errorf("RefreshInterval = %v, want %v", cfg.RefreshInterval, time.Second)
	}
	if len(cfg.Panels) == 0 {
		t.Error("Panels should not be empty")
	}
	if len(cfg.LatencyTargets) == 0 {
		t.Error("LatencyTargets should not be empty")
	}
}

func TestNew(t *testing.T) {
	d := New(Config{})
	if d.config.RefreshInterval != time.Second {
		t.Error("Default refresh interval not applied")
	}
}

func TestStartStop(t *testing.T) {
	d := New(Config{RefreshInterval: 100 * time.Millisecond, Simulate: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d.Start(ctx)
	time.Sleep(250 * time.Millisecond)
	d.Stop()

	// Should not panic on double stop
	d.Stop()
}

func TestGetStats(t *testing.T) {
	d := New(Config{Simulate: true})
	d.update()
	stats := d.GetStats()
	if stats.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestRender(t *testing.T) {
	d := New(Config{Simulate: true, LatencyTargets: []string{"8.8.8.8"}})
	d.update()
	output := d.Render(60)
	if output == "" {
		t.Error("Render returned empty string")
	}
}

func TestClearScreen(t *testing.T) {
	s := ClearScreen()
	if s == "" {
		t.Error("ClearScreen returned empty string")
	}
}
