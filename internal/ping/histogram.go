package ping

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// GenerateHistogram creates an ASCII histogram of RTT distribution.
func GenerateHistogram(rtts []time.Duration, width int) string {
	if len(rtts) == 0 {
		return "No data available for histogram"
	}

	if width <= 0 {
		width = 40 // Default width
	}

	// Find min and max for bucketing
	minRTT := rtts[0]
	maxRTT := rtts[0]
	for _, rtt := range rtts {
		if rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
	}

	// If all values are the same, show single bucket
	if minRTT == maxRTT {
		return fmt.Sprintf("%v: %s %d",
			formatDuration(minRTT),
			strings.Repeat("█", width),
			len(rtts))
	}

	// Create 10 buckets
	numBuckets := 10
	buckets := make([]int, numBuckets)
	bucketSize := (maxRTT - minRTT) / time.Duration(numBuckets)

	if bucketSize == 0 {
		bucketSize = 1
	}

	// Fill buckets
	for _, rtt := range rtts {
		bucketIndex := int((rtt - minRTT) / bucketSize)
		if bucketIndex >= numBuckets {
			bucketIndex = numBuckets - 1
		}
		buckets[bucketIndex]++
	}

	// Find max count for scaling
	maxCount := 0
	for _, count := range buckets {
		if count > maxCount {
			maxCount = count
		}
	}

	if maxCount == 0 {
		return "No data available for histogram"
	}

	// Build histogram
	var sb strings.Builder
	sb.WriteString("\nRTT Distribution:\n")

	for i, count := range buckets {
		if count == 0 {
			continue // Skip empty buckets
		}

		start := minRTT + time.Duration(i)*bucketSize
		end := start + bucketSize

		// Calculate bar length
		barLength := int(math.Ceil(float64(count) / float64(maxCount) * float64(width)))
		if barLength == 0 && count > 0 {
			barLength = 1
		}

		bar := strings.Repeat("█", barLength)

		sb.WriteString(fmt.Sprintf("%-10s: %s %d\n",
			formatRange(start, end),
			bar,
			count))
	}

	return sb.String()
}

// formatDuration formats a duration for display.
func formatDuration(d time.Duration) string {
	ms := d.Milliseconds()
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// formatRange formats a duration range for display.
func formatRange(start, end time.Duration) string {
	return fmt.Sprintf("%s-%s",
		formatDuration(start),
		formatDuration(end))
}
