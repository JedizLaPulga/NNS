package ping

import (
	"testing"
	"time"
)

func TestStatistics_AddRTT(t *testing.T) {
	stats := NewStatistics()

	stats.AddRTT(10 * time.Millisecond)
	stats.AddRTT(20 * time.Millisecond)
	stats.AddRTT(15 * time.Millisecond)

	if stats.Sent != 3 {
		t.Errorf("Sent = %d, want 3", stats.Sent)
	}

	if stats.Received != 3 {
		t.Errorf("Received = %d, want 3", stats.Received)
	}

	if stats.MinRTT != 10*time.Millisecond {
		t.Errorf("MinRTT = %v, want 10ms", stats.MinRTT)
	}

	if stats.MaxRTT != 20*time.Millisecond {
		t.Errorf("MaxRTT = %v, want 20ms", stats.MaxRTT)
	}
}

func TestStatistics_AddLost(t *testing.T) {
	stats := NewStatistics()

	stats.AddRTT(10 * time.Millisecond)
	stats.AddLost()
	stats.AddRTT(15 * time.Millisecond)
	stats.AddLost()

	if stats.Sent != 4 {
		t.Errorf("Sent = %d, want 4", stats.Sent)
	}

	if stats.Received != 2 {
		t.Errorf("Received = %d, want 2", stats.Received)
	}

	if stats.Lost != 2 {
		t.Errorf("Lost = %d, want 2", stats.Lost)
	}
}

func TestStatistics_Calculate(t *testing.T) {
	stats := NewStatistics()

	// Add test data: 10, 15, 20, 25, 30 ms
	rtts := []time.Duration{
		10 * time.Millisecond,
		15 * time.Millisecond,
		20 * time.Millisecond,
		25 * time.Millisecond,
		30 * time.Millisecond,
	}

	for _, rtt := range rtts {
		stats.AddRTT(rtt)
	}
	stats.AddLost() // One lost packet

	stats.Calculate()

	// Check loss rate
	if stats.Lost != 1 {
		t.Errorf("Lost = %d, want 1", stats.Lost)
	}

	expectedLossRate := float64(1) / float64(6) * 100.0 // 16.67%
	if stats.LossRate < 16.0 || stats.LossRate > 17.0 {
		t.Errorf("LossRate = %.2f%%, want ~16.67%% (expected %.2f%%)", stats.LossRate, expectedLossRate)
	}

	// Check average (10+15+20+25+30)/5 = 20ms
	if stats.AvgRTT != 20*time.Millisecond {
		t.Errorf("AvgRTT = %v, want 20ms", stats.AvgRTT)
	}

	// Check median (middle value of sorted list)
	if stats.MedianRTT != 20*time.Millisecond {
		t.Errorf("MedianRTT = %v, want 20ms", stats.MedianRTT)
	}

	// Check jitter (average absolute difference between consecutive values)
	// |15-10| + |20-15| + |25-20| + |30-25| = 5+5+5+5 = 20, avg = 5ms
	if stats.Jitter != 5*time.Millisecond {
		t.Errorf("Jitter = %v, want 5ms", stats.Jitter)
	}
}

func TestMedian(t *testing.T) {
	tests := []struct {
		name   string
		values []time.Duration
		want   time.Duration
	}{
		{
			name:   "empty",
			values: []time.Duration{},
			want:   0,
		},
		{
			name:   "single value",
			values: []time.Duration{10 * time.Millisecond},
			want:   10 * time.Millisecond,
		},
		{
			name:   "odd count",
			values: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond},
			want:   20 * time.Millisecond,
		},
		{
			name:   "even count",
			values: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond, 40 * time.Millisecond},
			want:   25 * time.Millisecond, // Average of 20 and 30
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := median(tt.values)
			if got != tt.want {
				t.Errorf("median() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPercentile(t *testing.T) {
	values := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
	}

	// 95th percentile of 5 values -> index 3.8 -> rounds to index 3 -> 40ms
	p95 := percentile(values, 0.95)
	if p95 != 50*time.Millisecond {
		t.Errorf("percentile(0.95) = %v, want 50ms", p95)
	}

	// 50th percentile (median) -> index 2 -> 30ms
	p50 := percentile(values, 0.50)
	if p50 != 30*time.Millisecond {
		t.Errorf("percentile(0.50) = %v, want 30ms", p50)
	}
}

func TestJitter(t *testing.T) {
	// Jitter should be average absolute difference between consecutive RTTs
	values := []time.Duration{
		10 * time.Millisecond,
		15 * time.Millisecond, // diff: 5
		20 * time.Millisecond, // diff: 5
		25 * time.Millisecond, // diff: 5
	}

	// Average jitter: (5+5+5)/3 = 5ms
	got := jitter(values)
	if got != 5*time.Millisecond {
		t.Errorf("jitter() = %v, want 5ms", got)
	}

	// Variable jitter
	values2 := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond, // diff: 10
		15 * time.Millisecond, // diff: 5
	}

	// Average: (10+5)/2 = 7.5ms
	got2 := jitter(values2)
	expected := 7500 * time.Microsecond
	if got2 != expected {
		t.Errorf("jitter() = %v, want %v", got2, expected)
	}
}

func TestQuality(t *testing.T) {
	tests := []struct {
		name     string
		lossRate float64
		avgRTT   time.Duration
		jitter   time.Duration
		want     string
	}{
		{
			name:     "excellent",
			lossRate: 0.5,
			avgRTT:   30 * time.Millisecond,
			jitter:   2 * time.Millisecond,
			want:     "Excellent",
		},
		{
			name:     "good",
			lossRate: 2.0,
			avgRTT:   80 * time.Millisecond,
			jitter:   8 * time.Millisecond,
			want:     "Good",
		},
		{
			name:     "fair",
			lossRate: 10.0,
			avgRTT:   150 * time.Millisecond,
			jitter:   15 * time.Millisecond,
			want:     "Fair",
		},
		{
			name:     "poor",
			lossRate: 20.0,
			avgRTT:   300 * time.Millisecond,
			jitter:   50 * time.Millisecond,
			want:     "Poor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := &Statistics{
				Received: 1,
				LossRate: tt.lossRate,
				AvgRTT:   tt.avgRTT,
				Jitter:   tt.jitter,
			}
			got := stats.Quality()
			if got != tt.want {
				t.Errorf("Quality() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateHistogram(t *testing.T) {
	rtts := []time.Duration{
		10 * time.Millisecond,
		15 * time.Millisecond,
		20 * time.Millisecond,
		25 * time.Millisecond,
		30 * time.Millisecond,
	}

	histogram := GenerateHistogram(rtts, 20)

	if histogram == "" {
		t.Error("GenerateHistogram() returned empty string")
	}

	// Should contain "RTT Distribution"
	if len(histogram) < 10 {
		t.Errorf("GenerateHistogram() output too short: %s", histogram)
	}
}

func BenchmarkStatisticsCalculate(b *testing.B) {
	stats := NewStatistics()

	// Add 100 RTT measurements
	for i := 0; i < 100; i++ {
		stats.AddRTT(time.Duration(i) * time.Millisecond)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.Calculate()
	}
}
