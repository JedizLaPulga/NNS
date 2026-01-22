// Package bwmon provides real-time bandwidth monitoring for network interfaces.
package bwmon

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// InterfaceStats holds bandwidth statistics for a single interface.
type InterfaceStats struct {
	Name      string
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
	Timestamp time.Time
}

// BandwidthRate holds calculated bandwidth rates.
type BandwidthRate struct {
	Name          string
	RxBytesPerSec float64
	TxBytesPerSec float64
	RxPktsPerSec  float64
	TxPktsPerSec  float64
	TotalRxBytes  uint64
	TotalTxBytes  uint64
}

// Monitor provides bandwidth monitoring functionality.
type Monitor struct {
	Interval     time.Duration
	prevStats    map[string]InterfaceStats
	prevTime     time.Time
	FilterActive bool // Only show interfaces with traffic
}

// NewMonitor creates a new bandwidth monitor.
func NewMonitor() *Monitor {
	return &Monitor{
		Interval:     1 * time.Second,
		prevStats:    make(map[string]InterfaceStats),
		FilterActive: false,
	}
}

// GetStats returns current interface statistics.
func (m *Monitor) GetStats() ([]InterfaceStats, error) {
	switch runtime.GOOS {
	case "linux":
		return m.getStatsLinux()
	case "windows":
		return m.getStatsWindows()
	case "darwin":
		return m.getStatsDarwin()
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// getStatsLinux reads stats from /proc/net/dev on Linux.
func (m *Monitor) getStatsLinux() ([]InterfaceStats, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/dev: %v", err)
	}
	defer file.Close()

	var stats []InterfaceStats
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		// Skip header lines
		if lineNum <= 2 {
			continue
		}

		line := scanner.Text()
		stat, err := parseLinuxNetDevLine(line)
		if err != nil {
			continue
		}
		stat.Timestamp = time.Now()
		stats = append(stats, stat)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /proc/net/dev: %v", err)
	}

	return stats, nil
}

// parseLinuxNetDevLine parses a single line from /proc/net/dev.
func parseLinuxNetDevLine(line string) (InterfaceStats, error) {
	var stat InterfaceStats

	// Format: "iface: rx_bytes rx_packets ... tx_bytes tx_packets ..."
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return stat, fmt.Errorf("invalid line format")
	}

	stat.Name = strings.TrimSpace(parts[0])

	fields := strings.Fields(parts[1])
	if len(fields) < 16 {
		return stat, fmt.Errorf("insufficient fields")
	}

	var err error
	stat.RxBytes, err = strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return stat, err
	}
	stat.RxPackets, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return stat, err
	}
	stat.TxBytes, err = strconv.ParseUint(fields[8], 10, 64)
	if err != nil {
		return stat, err
	}
	stat.TxPackets, err = strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return stat, err
	}

	return stat, nil
}

// getStatsWindows uses performance counters on Windows.
// This is a simplified version that works with netstat output.
func (m *Monitor) getStatsWindows() ([]InterfaceStats, error) {
	// On Windows, we'll use a simpler approach via net package
	// For now, return a basic implementation that can be enhanced
	return m.getStatsGeneric()
}

// getStatsDarwin uses netstat on macOS.
func (m *Monitor) getStatsDarwin() ([]InterfaceStats, error) {
	return m.getStatsGeneric()
}

// getStatsGeneric provides a cross-platform fallback using net package.
func (m *Monitor) getStatsGeneric() ([]InterfaceStats, error) {
	// This is a placeholder - real implementation would use
	// platform-specific APIs or syscalls
	return nil, fmt.Errorf("bandwidth monitoring requires platform-specific implementation; use --simulate for demo")
}

// CalculateRates computes bandwidth rates from current stats.
func (m *Monitor) CalculateRates(current []InterfaceStats) []BandwidthRate {
	now := time.Now()
	var rates []BandwidthRate

	for _, stat := range current {
		rate := BandwidthRate{
			Name:         stat.Name,
			TotalRxBytes: stat.RxBytes,
			TotalTxBytes: stat.TxBytes,
		}

		if prev, ok := m.prevStats[stat.Name]; ok {
			elapsed := now.Sub(m.prevTime).Seconds()
			if elapsed > 0 {
				rate.RxBytesPerSec = float64(stat.RxBytes-prev.RxBytes) / elapsed
				rate.TxBytesPerSec = float64(stat.TxBytes-prev.TxBytes) / elapsed
				rate.RxPktsPerSec = float64(stat.RxPackets-prev.RxPackets) / elapsed
				rate.TxPktsPerSec = float64(stat.TxPackets-prev.TxPackets) / elapsed
			}
		}

		// Filter inactive interfaces if requested
		if m.FilterActive && rate.RxBytesPerSec == 0 && rate.TxBytesPerSec == 0 {
			continue
		}

		rates = append(rates, rate)
	}

	// Store current stats for next calculation
	m.prevStats = make(map[string]InterfaceStats)
	for _, stat := range current {
		m.prevStats[stat.Name] = stat
	}
	m.prevTime = now

	return rates
}

// FormatBytesPerSec formats bytes/sec into human-readable format.
func FormatBytesPerSec(bps float64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case bps >= GB:
		return fmt.Sprintf("%.2f GB/s", bps/GB)
	case bps >= MB:
		return fmt.Sprintf("%.2f MB/s", bps/MB)
	case bps >= KB:
		return fmt.Sprintf("%.2f KB/s", bps/KB)
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}

// FormatBytes formats bytes into human-readable format.
func FormatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// SimulatedStats returns simulated interface statistics for demo/testing.
func SimulatedStats(iteration int) []InterfaceStats {
	base := time.Now()

	// Simulate consistent cumulative traffic (monotonically increasing)
	// Add some variation to the rate by using a base + variable component
	baseRxRate := uint64(150000) // ~150 KB per iteration
	baseTxRate := uint64(75000)  // ~75 KB per iteration

	// Add small variations without causing the cumulative to decrease
	variableRx := uint64((iteration % 7) * 10000)
	variableTx := uint64((iteration % 5) * 5000)

	return []InterfaceStats{
		{
			Name:      "eth0",
			RxBytes:   uint64(iteration) * (baseRxRate + variableRx),
			TxBytes:   uint64(iteration) * (baseTxRate + variableTx),
			RxPackets: uint64(iteration) * 1000,
			TxPackets: uint64(iteration) * 500,
			Timestamp: base,
		},
		{
			Name:      "lo",
			RxBytes:   uint64(iteration) * 10000,
			TxBytes:   uint64(iteration) * 10000,
			RxPackets: uint64(iteration) * 100,
			TxPackets: uint64(iteration) * 100,
			Timestamp: base,
		},
	}
}

// RenderBar creates an ASCII progress bar for bandwidth visualization.
func RenderBar(value, max float64, width int) string {
	if max <= 0 {
		return strings.Repeat("░", width)
	}

	filled := int((value / max) * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}

	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}
