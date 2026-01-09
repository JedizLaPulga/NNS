// Package stats provides shared statistical calculations and visualization tools.
package stats

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Mean calculates the arithmetic mean of a slice of float64 values.
func Mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// Median calculates the median value from a slice of float64 values.
func Median(values []float64) float64 {
	return Percentile(values, 0.5)
}

// Percentile calculates the percentile value (p between 0.0 and 1.0).
// Values slice must be sorted? No, we'll sort a copy to be safe/pure.
func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}

	// Create a copy to avoid modifying original
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	index := int(math.Round(float64(len(sorted)-1) * p))
	return sorted[index]
}

// StdDev calculates standard deviation of values.
func StdDev(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	mean := Mean(values)
	var sumSquaredDiff float64
	for _, v := range values {
		diff := v - mean
		sumSquaredDiff += diff * diff
	}

	variance := sumSquaredDiff / float64(len(values))
	return math.Sqrt(variance)
}

// GenerateHistogram creates an ASCII histogram of value distribution.
// If unit is provided (e.g., "ms"), it formats the range labels.
func GenerateHistogram(values []float64, width int, unitMultiplier float64, unitName string) string {
	if len(values) == 0 {
		return "No data available for histogram"
	}

	if width <= 0 {
		width = 40 // Default width
	}

	// Calc min/max
	minVal := values[0]
	maxVal := values[0]
	for _, v := range values {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	// Check for single value case
	if minVal == maxVal {
		return fmt.Sprintf("%s: %s %d",
			formatValue(minVal, unitMultiplier, unitName),
			strings.Repeat("█", width),
			len(values))
	}

	// Create buckets
	numBuckets := 10
	buckets := make([]int, numBuckets)
	range_ := maxVal - minVal
	bucketSize := range_ / float64(numBuckets)

	if bucketSize == 0 {
		bucketSize = 1
	}

	// Fill buckets
	for _, v := range values {
		idx := int((v - minVal) / bucketSize)
		if idx >= numBuckets {
			idx = numBuckets - 1
		}
		if idx < 0 {
			idx = 0
		}
		buckets[idx]++
	}

	// Find max count for scaling
	maxCount := 0
	for _, count := range buckets {
		if count > maxCount {
			maxCount = count
		}
	}

	// Build string
	var sb strings.Builder
	sb.WriteString("\nDistribution:\n")

	for i, count := range buckets {
		if count == 0 {
			continue
		}

		start := minVal + float64(i)*bucketSize
		end := start + bucketSize

		barLength := int(math.Ceil(float64(count) / float64(maxCount) * float64(width)))
		if barLength == 0 && count > 0 {
			barLength = 1
		}

		bar := strings.Repeat("█", barLength)

		label := fmt.Sprintf("%s-%s",
			formatValue(start, unitMultiplier, unitName),
			formatValue(end, unitMultiplier, unitName))

		sb.WriteString(fmt.Sprintf("%-16s: %s %d\n", label, bar, count))
	}

	return sb.String()
}

func formatValue(val float64, mult float64, unit string) string {
	if unit == "" {
		return fmt.Sprintf("%.2f", val)
	}
	// For time durations passed as float64 ns
	if unit == "s" || unit == "ms" {
		// Expect input val to be in seconds if unit is "s", or whatever base
		// Let's assume input is generic float, mult converts to display unit
		v := val * mult
		return fmt.Sprintf("%.0f%s", v, unit)
	}
	return fmt.Sprintf("%.2f%s", val*mult, unit)
}

// DurationsToFloat converts []time.Duration to []float64 (in seconds).
func DurationsToFloat(ds []time.Duration) []float64 {
	fs := make([]float64, len(ds))
	for i, d := range ds {
		fs[i] = d.Seconds()
	}
	return fs
}
