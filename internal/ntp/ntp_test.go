package ntp

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 5*time.Second {
		t.Errorf("DefaultConfig().Timeout = %v, want 5s", cfg.Timeout)
	}
	if len(cfg.Servers) == 0 {
		t.Error("DefaultConfig().Servers should not be empty")
	}
}

func TestNew(t *testing.T) {
	checker := New(Config{})

	if checker.config.Timeout != 5*time.Second {
		t.Errorf("New().config.Timeout = %v, want 5s", checker.config.Timeout)
	}
	if len(checker.config.Servers) == 0 {
		t.Error("New().config.Servers should not be empty")
	}
}

func TestPublicServers(t *testing.T) {
	if len(PublicServers) == 0 {
		t.Error("PublicServers should not be empty")
	}

	// Check for well-known servers
	hasPool := false
	hasGoogle := false
	for _, s := range PublicServers {
		if s.Name == "pool.ntp.org" {
			hasPool = true
		}
		if s.Name == "time.google.com" {
			hasGoogle = true
		}
	}

	if !hasPool {
		t.Error("PublicServers should contain pool.ntp.org")
	}
	if !hasGoogle {
		t.Error("PublicServers should contain time.google.com")
	}
}

func TestNtpToTime(t *testing.T) {
	// Test with known epoch value
	// NTP timestamp for Unix epoch (1970-01-01) is 2208988800
	unixTime := ntpToTime(ntpEpochOffset, 0)

	if unixTime.Year() != 1970 {
		t.Errorf("ntpToTime(ntpEpochOffset, 0).Year() = %d, want 1970", unixTime.Year())
	}
}

func TestParseReferenceID(t *testing.T) {
	// Test stratum 1 (ASCII)
	data := []byte{'G', 'P', 'S', 0}
	result := parseReferenceID(data, 1)
	if result != "GPS" {
		t.Errorf("parseReferenceID stratum 1 = %s, want GPS", result)
	}

	// Test stratum 2 (IPv4)
	data = []byte{192, 168, 1, 1}
	result = parseReferenceID(data, 2)
	if result != "192.168.1.1" {
		t.Errorf("parseReferenceID stratum 2 = %s, want 192.168.1.1", result)
	}
}

func TestAbsOffset(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected time.Duration
	}{
		{100 * time.Millisecond, 100 * time.Millisecond},
		{-100 * time.Millisecond, 100 * time.Millisecond},
		{0, 0},
	}

	for _, tt := range tests {
		result := absOffset(tt.input)
		if result != tt.expected {
			t.Errorf("absOffset(%v) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestFormatOffset(t *testing.T) {
	result := formatOffset(100 * time.Millisecond)
	if result != "+100ms" {
		t.Errorf("formatOffset(100ms) = %s, want +100ms", result)
	}

	result = formatOffset(-100 * time.Millisecond)
	if result != "-100ms" {
		t.Errorf("formatOffset(-100ms) = %s, want -100ms", result)
	}
}

func TestCheckResultFormat(t *testing.T) {
	result := &CheckResult{
		Results: []Result{
			{
				Server:    Server{Name: "test.ntp.org"},
				Reachable: true,
				RTT:       50 * time.Millisecond,
				Offset:    10 * time.Millisecond,
				Stratum:   2,
			},
		},
		BestServer:   &Result{Server: Server{Name: "test.ntp.org"}, RTT: 50 * time.Millisecond},
		AvgOffset:    10 * time.Millisecond,
		LocalClockOK: true,
		Duration:     1 * time.Second,
	}

	output := result.Format()

	if output == "" {
		t.Error("Format() returned empty string")
	}
	if len(output) < 50 {
		t.Error("Format() output too short")
	}
}

func TestQueryServerTimeout(t *testing.T) {
	cfg := Config{
		Servers: []Server{{Name: "test", Address: "10.255.255.1:123"}},
		Timeout: 100 * time.Millisecond,
	}
	checker := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result := checker.QueryServer(ctx, cfg.Servers[0])

	if result.Reachable {
		t.Log("QueryServer to unreachable host returned reachable (network dependent)")
	}
}

func TestAnalyzeResults(t *testing.T) {
	checker := New(DefaultConfig())

	result := &CheckResult{
		Results: []Result{
			{Reachable: true, Offset: 10 * time.Millisecond, RTT: 50 * time.Millisecond},
			{Reachable: true, Offset: 20 * time.Millisecond, RTT: 60 * time.Millisecond},
			{Reachable: false},
		},
	}

	checker.analyzeResults(result)

	if result.BestServer == nil {
		t.Error("analyzeResults should set BestServer")
	}
	if result.AvgOffset != 15*time.Millisecond {
		t.Errorf("AvgOffset = %v, want 15ms", result.AvgOffset)
	}
	if !result.LocalClockOK {
		t.Error("LocalClockOK should be true for 15ms offset")
	}
}
