// Package ping provides enhanced ICMP ping functionality with advanced statistics.
package ping

import (
	"math"
	"sort"
	"time"
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

	// Average RTT
	var sum time.Duration
	for _, rtt := range s.RTTs {
		sum += rtt
	}
	s.AvgRTT = sum / time.Duration(s.Received)

	// Median RTT
	s.MedianRTT = median(s.RTTs)

	// Standard deviation
	s.StdDev = stddev(s.RTTs, s.AvgRTT)

	// Jitter
	s.Jitter = jitter(s.RTTs)

	// Percentiles
	s.P95 = percentile(s.RTTs, 0.95)
	s.P99 = percentile(s.RTTs, 0.99)
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

// median calculates the median value from a slice of durations.
func median(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}

	// Make a copy to avoid modifying original
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	n := len(sorted)
	if n%2 == 0 {
		// Even number: average of two middle values
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	// Odd number: middle value
	return sorted[n/2]
}

// percentile calculates the percentile value (p between 0.0 and 1.0).
func percentile(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}

	// Make a copy to avoid modifying original
	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	index := int(float64(len(sorted)-1) * p)
	return sorted[index]
}

// stddev calculates standard deviation of durations.
func stddev(values []time.Duration, mean time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}

	var sumSquaredDiff float64
	for _, v := range values {
		diff := float64(v - mean)
		sumSquaredDiff += diff * diff
	}

	variance := sumSquaredDiff / float64(len(values))
	return time.Duration(math.Sqrt(variance))
}

// jitter calculates average jitter (variation between consecutive RTTs).
func jitter(values []time.Duration) time.Duration {
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
