package bwmon

import (
	"testing"
	"time"
)

func TestNewMonitor(t *testing.T) {
	m := NewMonitor()
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}
	if m.Interval != 1*time.Second {
		t.Errorf("expected default interval 1s, got %v", m.Interval)
	}
	if m.prevStats == nil {
		t.Error("expected prevStats to be initialized")
	}
}

func TestFormatBytesPerSec(t *testing.T) {
	tests := []struct {
		bps      float64
		expected string
	}{
		{0, "0 B/s"},
		{500, "500 B/s"},
		{1024, "1.00 KB/s"},
		{1536, "1.50 KB/s"},
		{1048576, "1.00 MB/s"},
		{1572864, "1.50 MB/s"},
		{1073741824, "1.00 GB/s"},
	}

	for _, tt := range tests {
		result := FormatBytesPerSec(tt.bps)
		if result != tt.expected {
			t.Errorf("FormatBytesPerSec(%f) = %s, want %s", tt.bps, result, tt.expected)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.00 KB"},
		{1048576, "1.00 MB"},
		{1073741824, "1.00 GB"},
		{1099511627776, "1.00 TB"},
	}

	for _, tt := range tests {
		result := FormatBytes(tt.bytes)
		if result != tt.expected {
			t.Errorf("FormatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
		}
	}
}

func TestSimulatedStats(t *testing.T) {
	stats := SimulatedStats(1)
	if len(stats) != 2 {
		t.Errorf("expected 2 simulated interfaces, got %d", len(stats))
	}

	// Check eth0
	if stats[0].Name != "eth0" {
		t.Errorf("expected first interface 'eth0', got '%s'", stats[0].Name)
	}
	if stats[0].RxBytes == 0 {
		t.Error("expected non-zero RxBytes for eth0")
	}

	// Check lo
	if stats[1].Name != "lo" {
		t.Errorf("expected second interface 'lo', got '%s'", stats[1].Name)
	}
}

func TestCalculateRates(t *testing.T) {
	m := NewMonitor()

	// First sample (no previous data)
	stats1 := []InterfaceStats{
		{Name: "eth0", RxBytes: 1000, TxBytes: 500, RxPackets: 10, TxPackets: 5},
	}
	rates1 := m.CalculateRates(stats1)
	if len(rates1) != 1 {
		t.Fatalf("expected 1 rate, got %d", len(rates1))
	}
	// First calculation should have zero rates (no previous sample)
	if rates1[0].RxBytesPerSec != 0 {
		t.Errorf("expected 0 RxBytesPerSec on first sample, got %f", rates1[0].RxBytesPerSec)
	}

	// Wait a bit and take second sample
	time.Sleep(100 * time.Millisecond)

	stats2 := []InterfaceStats{
		{Name: "eth0", RxBytes: 2000, TxBytes: 1000, RxPackets: 20, TxPackets: 10},
	}
	rates2 := m.CalculateRates(stats2)
	if len(rates2) != 1 {
		t.Fatalf("expected 1 rate, got %d", len(rates2))
	}

	// Second calculation should have non-zero rates
	if rates2[0].RxBytesPerSec <= 0 {
		t.Errorf("expected positive RxBytesPerSec, got %f", rates2[0].RxBytesPerSec)
	}
	if rates2[0].TxBytesPerSec <= 0 {
		t.Errorf("expected positive TxBytesPerSec, got %f", rates2[0].TxBytesPerSec)
	}
}

func TestCalculateRatesFilterActive(t *testing.T) {
	m := NewMonitor()
	m.FilterActive = true

	// First sample
	stats1 := []InterfaceStats{
		{Name: "eth0", RxBytes: 1000, TxBytes: 500},
		{Name: "lo", RxBytes: 0, TxBytes: 0},
	}
	m.CalculateRates(stats1)

	time.Sleep(50 * time.Millisecond)

	// Second sample - eth0 has traffic, lo doesn't
	stats2 := []InterfaceStats{
		{Name: "eth0", RxBytes: 2000, TxBytes: 1000},
		{Name: "lo", RxBytes: 0, TxBytes: 0},
	}
	rates := m.CalculateRates(stats2)

	// Should only include eth0 since lo has no traffic
	if len(rates) != 1 {
		t.Errorf("expected 1 active interface, got %d", len(rates))
	}
	if len(rates) > 0 && rates[0].Name != "eth0" {
		t.Errorf("expected 'eth0', got '%s'", rates[0].Name)
	}
}

func TestRenderBar(t *testing.T) {
	tests := []struct {
		value    float64
		max      float64
		width    int
		expected string
	}{
		{0, 100, 10, "░░░░░░░░░░"},
		{50, 100, 10, "█████░░░░░"},
		{100, 100, 10, "██████████"},
		{150, 100, 10, "██████████"}, // Clamp to max
		{0, 0, 10, "░░░░░░░░░░"},     // Handle zero max
	}

	for _, tt := range tests {
		result := RenderBar(tt.value, tt.max, tt.width)
		if result != tt.expected {
			t.Errorf("RenderBar(%f, %f, %d) = %s, want %s", tt.value, tt.max, tt.width, result, tt.expected)
		}
	}
}

func TestParseLinuxNetDevLine(t *testing.T) {
	line := "  eth0: 123456789  1000    0    0    0     0          0         0   987654321  2000    0    0    0     0       0          0"
	stat, err := parseLinuxNetDevLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stat.Name != "eth0" {
		t.Errorf("expected name 'eth0', got '%s'", stat.Name)
	}
	if stat.RxBytes != 123456789 {
		t.Errorf("expected RxBytes 123456789, got %d", stat.RxBytes)
	}
	if stat.RxPackets != 1000 {
		t.Errorf("expected RxPackets 1000, got %d", stat.RxPackets)
	}
	if stat.TxBytes != 987654321 {
		t.Errorf("expected TxBytes 987654321, got %d", stat.TxBytes)
	}
	if stat.TxPackets != 2000 {
		t.Errorf("expected TxPackets 2000, got %d", stat.TxPackets)
	}
}

func TestParseLinuxNetDevLineInvalid(t *testing.T) {
	tests := []string{
		"invalid line without colon",
		"eth0: too few fields",
		"",
	}

	for _, line := range tests {
		_, err := parseLinuxNetDevLine(line)
		if err == nil {
			t.Errorf("expected error for line: %s", line)
		}
	}
}
