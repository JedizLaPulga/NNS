// Package ping provides enhanced ICMP ping functionality with advanced statistics.
package ping

import (
	"time"

	"github.com/JedizLaPulga/NNS/internal/stats"
)

// Statistics holds comprehensive ping statistics and metrics.
type Statistics struct {
	Sent      int
	Received  int
	Lost      int
	LossRate  float64
	MinRTT    time.Duration
	MaxRTT    time.Duration
	AvgRTT    time.Duration
	MedianRTT time.Duration
	Jitter    time.Duration
	StdDev    time.Duration
	P95       time.Duration // 95th percentile
	P99       time.Duration // 99th percentile
	RTTs      []time.Duration
}

// NewStatistics creates a new Statistics instance.
func NewStatistics() *Statistics {
	return &Statistics{
		RTTs: make([]time.Duration, 0),
	}
}

// AddRTT adds a successful RTT measurement to statistics.
func (s *Statistics) AddRTT(rtt time.Duration) {
	s.Sent++
	s.Received++
	s.RTTs = append(s.RTTs, rtt)

	// Update min/max
	if s.MinRTT == 0 || rtt < s.MinRTT {
		s.MinRTT = rtt
	}
	if rtt > s.MaxRTT {
		s.MaxRTT = rtt
	}
}

// AddLost records a lost packet.
func (s *Statistics) AddLost() {
	s.Sent++
	s.Lost++
}

// Calculate computes all derived statistics.
func (s *Statistics) Calculate() {
	if s.Sent == 0 {
		return
	}

	// Loss rate
	s.LossRate = float64(s.Lost) / float64(s.Sent) * 100.0

	if s.Received == 0 {
		return
	}

	// Convert Durations to float64 (seconds) for stats package
	vals := stats.DurationsToFloat(s.RTTs)

	// Average RTT (we can do this without float conversion loop if we want, but stats package has Mean)
	var sum time.Duration
	for _, rtt := range s.RTTs {
		sum += rtt
	}
	s.AvgRTT = sum / time.Duration(s.Received)

	// Median RTT
	s.MedianRTT = time.Duration(stats.Median(vals) * float64(time.Second))

	// Standard deviation
	s.StdDev = time.Duration(stats.StdDev(vals) * float64(time.Second))

	// Jitter (local implementation best for duration slices)
	s.Jitter = calculateJitter(s.RTTs)

	// Percentiles
	s.P95 = time.Duration(stats.Percentile(vals, 0.95) * float64(time.Second))
	s.P99 = time.Duration(stats.Percentile(vals, 0.99) * float64(time.Second))
}

// Quality returns a quality rating based on packet loss, RTT, and jitter.
func (s *Statistics) Quality() string {
	if s.Received == 0 {
		return "Unknown"
	}

	avgMS := float64(s.AvgRTT.Milliseconds())
	jitterMS := float64(s.Jitter.Milliseconds())

	// Excellent: Loss < 1%, Avg RTT < 50ms, Jitter < 5ms
	if s.LossRate < 1.0 && avgMS < 50.0 && jitterMS < 5.0 {
		return "Excellent"
	}

	// Good: Loss < 5%, Avg RTT < 100ms, Jitter < 10ms
	if s.LossRate < 5.0 && avgMS < 100.0 && jitterMS < 10.0 {
		return "Good"
	}

	// Fair: Loss < 15%, Avg RTT < 200ms, Jitter < 20ms
	if s.LossRate < 15.0 && avgMS < 200.0 && jitterMS < 20.0 {
		return "Fair"
	}

	return "Poor"
}

// calculateJitter computes average jitter locally to avoid float conversion overhead for diffs
func calculateJitter(values []time.Duration) time.Duration {
	if len(values) < 2 {
		return 0
	}

	var sumDiff time.Duration
	for i := 1; i < len(values); i++ {
		diff := values[i] - values[i-1]
		if diff < 0 {
			diff = -diff
		}
		sumDiff += diff
	}

	return sumDiff / time.Duration(len(values)-1)
}

// GenerateHistogram returns formatted histogram string using shared stats package
func GenerateHistogram(rtts []time.Duration, width int) string {
	vals := stats.DurationsToFloat(rtts)
	// Use 'ms' unit, multiplier 1000
	return stats.GenerateHistogram(vals, width, 1000.0, "ms")
}
