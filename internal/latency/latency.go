// Package latency provides continuous latency monitoring with visualization and alerting.
package latency

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sparkline characters for visualization (8 levels).
var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// Config holds configuration for the latency monitor.
type Config struct {
	Target    string        // Target host (hostname or IP)
	Port      int           // Target port (default: 443)
	Interval  time.Duration // Time between probes
	Timeout   time.Duration // Connection timeout per probe
	Threshold time.Duration // Alert threshold (0 = disabled)
	Count     int           // Number of probes (0 = infinite)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Port:      443,
		Interval:  time.Second,
		Timeout:   5 * time.Second,
		Threshold: 0,
		Count:     0,
	}
}

// Result represents a single latency probe result.
type Result struct {
	Seq       int           // Sequence number
	Latency   time.Duration // Round-trip time (0 if failed)
	Error     error         // Error if probe failed
	Timestamp time.Time     // Time of probe
	Alert     bool          // True if latency exceeds threshold
}

// Stats holds cumulative latency statistics.
type Stats struct {
	Sent     int           // Total probes sent
	Received int           // Successful probes
	Lost     int           // Failed probes
	Min      time.Duration // Minimum latency
	Max      time.Duration // Maximum latency
	Avg      time.Duration // Average latency
	P50      time.Duration // 50th percentile
	P95      time.Duration // 95th percentile
	P99      time.Duration // 99th percentile
	StdDev   time.Duration // Standard deviation
	Jitter   time.Duration // Average jitter (change between samples)
	Alerts   int           // Number of threshold alerts
}

// LossPercent returns the packet loss percentage.
func (s Stats) LossPercent() float64 {
	if s.Sent == 0 {
		return 0
	}
	return float64(s.Lost) / float64(s.Sent) * 100
}

// Monitor represents a latency monitor instance.
type Monitor struct {
	config   Config
	results  []Result
	mu       sync.RWMutex
	callback func(Result)
}

// New creates a new latency monitor with the given configuration.
func New(cfg Config) (*Monitor, error) {
	if cfg.Target == "" {
		return nil, errors.New("target is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		cfg.Port = 443
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &Monitor{
		config:  cfg,
		results: make([]Result, 0, 100),
	}, nil
}

// OnResult sets a callback function that is called for each probe result.
func (m *Monitor) OnResult(fn func(Result)) {
	m.callback = fn
}

// Run starts the latency monitoring loop. It blocks until the context is
// cancelled or the probe count is reached.
func (m *Monitor) Run(ctx context.Context) error {
	addr := net.JoinHostPort(m.config.Target, fmt.Sprintf("%d", m.config.Port))
	seq := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		seq++
		result := m.probe(addr, seq)

		m.mu.Lock()
		m.results = append(m.results, result)
		m.mu.Unlock()

		if m.callback != nil {
			m.callback(result)
		}

		if m.config.Count > 0 && seq >= m.config.Count {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.config.Interval):
		}
	}
}

// probe performs a single TCP connection probe.
func (m *Monitor) probe(addr string, seq int) Result {
	result := Result{
		Seq:       seq,
		Timestamp: time.Now(),
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, m.config.Timeout)
	result.Latency = time.Since(start)

	if err != nil {
		result.Error = err
		result.Latency = 0
	} else {
		conn.Close()
	}

	if m.config.Threshold > 0 && result.Latency > m.config.Threshold {
		result.Alert = true
	}

	return result
}

// Results returns a copy of all probe results.
func (m *Monitor) Results() []Result {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make([]Result, len(m.results))
	copy(cp, m.results)
	return cp
}

// Stats calculates and returns cumulative statistics.
func (m *Monitor) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.results) == 0 {
		return Stats{}
	}

	var stats Stats
	var latencies []time.Duration
	var prevLatency time.Duration
	var jitterSum time.Duration

	for i, r := range m.results {
		stats.Sent++
		if r.Error != nil {
			stats.Lost++
			continue
		}
		stats.Received++
		latencies = append(latencies, r.Latency)

		if r.Alert {
			stats.Alerts++
		}

		if i > 0 && prevLatency > 0 {
			diff := r.Latency - prevLatency
			if diff < 0 {
				diff = -diff
			}
			jitterSum += diff
		}
		prevLatency = r.Latency
	}

	if len(latencies) == 0 {
		return stats
	}

	// Sort for percentile calculations
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	stats.Min = sorted[0]
	stats.Max = sorted[len(sorted)-1]
	stats.P50 = percentile(sorted, 50)
	stats.P95 = percentile(sorted, 95)
	stats.P99 = percentile(sorted, 99)

	// Average
	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	stats.Avg = sum / time.Duration(len(latencies))

	// Standard deviation
	var variance float64
	avgFloat := float64(stats.Avg)
	for _, l := range latencies {
		diff := float64(l) - avgFloat
		variance += diff * diff
	}
	variance /= float64(len(latencies))
	stats.StdDev = time.Duration(math.Sqrt(variance))

	// Jitter
	if len(latencies) > 1 {
		stats.Jitter = jitterSum / time.Duration(len(latencies)-1)
	}

	return stats
}

// percentile calculates the p-th percentile of a sorted slice.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(p) / 100.0 * float64(len(sorted)-1))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// Sparkline generates a sparkline string from the last n results.
func (m *Monitor) Sparkline(n int) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.results) == 0 {
		return ""
	}

	start := 0
	if len(m.results) > n {
		start = len(m.results) - n
	}
	subset := m.results[start:]

	// Find min/max for scaling
	var min, max time.Duration
	min = time.Hour // Start high
	for _, r := range subset {
		if r.Error == nil {
			if r.Latency < min {
				min = r.Latency
			}
			if r.Latency > max {
				max = r.Latency
			}
		}
	}

	if max == min {
		max = min + 1 // Avoid division by zero
	}

	var sb strings.Builder
	for _, r := range subset {
		if r.Error != nil {
			sb.WriteRune('✕') // Failed probe
			continue
		}
		// Scale to 0-7 range
		scaled := float64(r.Latency-min) / float64(max-min)
		idx := int(scaled * 7)
		if idx > 7 {
			idx = 7
		}
		sb.WriteRune(sparkChars[idx])
	}

	return sb.String()
}

// FormatResult formats a single result for display.
func FormatResult(r Result, target string) string {
	if r.Error != nil {
		return fmt.Sprintf("seq=%d ✕ error: %v", r.Seq, r.Error)
	}
	alert := ""
	if r.Alert {
		alert = " ⚠️ ALERT"
	}
	return fmt.Sprintf("seq=%d time=%.2fms%s", r.Seq, float64(r.Latency.Microseconds())/1000.0, alert)
}

// FormatStats formats statistics for display.
func FormatStats(s Stats) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- Latency Statistics ---\n"))
	sb.WriteString(fmt.Sprintf("Probes: %d sent, %d received, %.1f%% loss\n", s.Sent, s.Received, s.LossPercent()))
	if s.Received > 0 {
		sb.WriteString(fmt.Sprintf("RTT: min=%.2fms avg=%.2fms max=%.2fms stddev=%.2fms\n",
			float64(s.Min.Microseconds())/1000.0,
			float64(s.Avg.Microseconds())/1000.0,
			float64(s.Max.Microseconds())/1000.0,
			float64(s.StdDev.Microseconds())/1000.0))
		sb.WriteString(fmt.Sprintf("Percentiles: p50=%.2fms p95=%.2fms p99=%.2fms\n",
			float64(s.P50.Microseconds())/1000.0,
			float64(s.P95.Microseconds())/1000.0,
			float64(s.P99.Microseconds())/1000.0))
		sb.WriteString(fmt.Sprintf("Jitter: %.2fms\n", float64(s.Jitter.Microseconds())/1000.0))
	}
	if s.Alerts > 0 {
		sb.WriteString(fmt.Sprintf("Alerts: %d threshold violations\n", s.Alerts))
	}
	return sb.String()
}
