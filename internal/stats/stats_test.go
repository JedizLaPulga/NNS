package stats

import (
	"math"
	"testing"
	"time"
)

func TestMean(t *testing.T) {
	tests := []struct {
		values []float64
		want   float64
	}{
		{[]float64{1, 2, 3, 4, 5}, 3.0},
		{[]float64{10, 20}, 15.0},
		{[]float64{5}, 5.0},
		{[]float64{}, 0.0},
	}

	for _, tt := range tests {
		got := Mean(tt.values)
		if got != tt.want {
			t.Errorf("Mean(%v) = %v, want %v", tt.values, got, tt.want)
		}
	}
}

func TestMedian(t *testing.T) {
	tests := []struct {
		values []float64
		want   float64
	}{
		{[]float64{1, 2, 3, 4, 5}, 3.0},
		{[]float64{1, 2, 3, 4}, 3.0}, // Middle of 2 and 3, using round
		{[]float64{5}, 5.0},
		{[]float64{}, 0.0},
	}

	for _, tt := range tests {
		got := Median(tt.values)
		if got != tt.want {
			t.Errorf("Median(%v) = %v, want %v", tt.values, got, tt.want)
		}
	}
}

func TestPercentile(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// Test P50 (median)
	p50 := Percentile(values, 0.5)
	if p50 < 5 || p50 > 6 {
		t.Errorf("Percentile(50) = %v, expected around 5-6", p50)
	}

	// Test P90
	p90 := Percentile(values, 0.9)
	if p90 < 9 || p90 > 10 {
		t.Errorf("Percentile(90) = %v, expected around 9-10", p90)
	}

	// Test empty
	empty := Percentile([]float64{}, 0.5)
	if empty != 0 {
		t.Errorf("Percentile of empty should be 0")
	}
}

func TestStdDev(t *testing.T) {
	// Known case: [2, 4, 4, 4, 5, 5, 7, 9] has stddev = 2
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	got := StdDev(values)

	if math.Abs(got-2.0) > 0.01 {
		t.Errorf("StdDev(%v) = %v, want 2.0", values, got)
	}

	// Empty case
	if StdDev([]float64{}) != 0 {
		t.Error("StdDev of empty should be 0")
	}
}

func TestDurationsToFloat(t *testing.T) {
	durations := []time.Duration{
		time.Second,
		2 * time.Second,
		500 * time.Millisecond,
	}

	floats := DurationsToFloat(durations)

	if len(floats) != 3 {
		t.Fatalf("Expected 3 floats, got %d", len(floats))
	}

	if floats[0] != 1.0 {
		t.Errorf("1 second should be 1.0, got %v", floats[0])
	}

	if floats[1] != 2.0 {
		t.Errorf("2 seconds should be 2.0, got %v", floats[1])
	}

	if floats[2] != 0.5 {
		t.Errorf("500ms should be 0.5, got %v", floats[2])
	}
}

func TestGenerateHistogram(t *testing.T) {
	values := []float64{1, 1, 2, 2, 2, 3, 3, 3, 3, 4}

	result := GenerateHistogram(values, 20, 1.0, "")

	if result == "" {
		t.Error("Histogram should not be empty")
	}

	if !contains(result, "Distribution") {
		t.Error("Histogram should contain 'Distribution' header")
	}
}

func TestGenerateHistogramEmpty(t *testing.T) {
	result := GenerateHistogram([]float64{}, 20, 1.0, "")

	if !contains(result, "No data") {
		t.Error("Empty histogram should say 'No data'")
	}
}

func TestGenerateHistogramSingleValue(t *testing.T) {
	result := GenerateHistogram([]float64{5, 5, 5}, 20, 1.0, "")

	if result == "" {
		t.Error("Single value histogram should not be empty")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func BenchmarkMean(b *testing.B) {
	values := make([]float64, 1000)
	for i := range values {
		values[i] = float64(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Mean(values)
	}
}
