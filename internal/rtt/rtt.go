// Package rtt provides round-trip time comparison across multiple hosts.
package rtt

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Protocol specifies the connection protocol.
type Protocol int

const (
	TCP Protocol = iota
	UDP
	ICMP
)

func (p Protocol) String() string {
	switch p {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case ICMP:
		return "ICMP"
	default:
		return "Unknown"
	}
}

// Target represents a host to measure RTT.
type Target struct {
	Host     string
	Port     int
	Name     string   // Optional friendly name
	Protocol Protocol // TCP, UDP, ICMP
}

// String returns target display name.
func (t Target) String() string {
	if t.Name != "" {
		return t.Name
	}
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// Address returns host:port formatted string.
func (t Target) Address() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// Measurement represents a single RTT measurement.
type Measurement struct {
	Time    time.Time
	RTT     time.Duration
	Success bool
	Error   error
}

// Result holds RTT measurements for a target.
type Result struct {
	Target       Target
	Measurements []Measurement
	MinRTT       time.Duration
	MaxRTT       time.Duration
	AvgRTT       time.Duration
	MedianRTT    time.Duration
	StdDev       time.Duration
	Jitter       time.Duration // Average difference between consecutive RTTs
	PacketLoss   float64       // Percentage
	Successful   int
	Failed       int
}

// Calculate computes statistics from measurements.
func (r *Result) Calculate() {
	if len(r.Measurements) == 0 {
		return
	}

	var rtts []time.Duration
	for _, m := range r.Measurements {
		if m.Success {
			rtts = append(rtts, m.RTT)
			r.Successful++
		} else {
			r.Failed++
		}
	}

	total := r.Successful + r.Failed
	if total > 0 {
		r.PacketLoss = float64(r.Failed) / float64(total) * 100
	}

	if len(rtts) == 0 {
		return
	}

	// Sort for stats
	sorted := make([]time.Duration, len(rtts))
	copy(sorted, rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	r.MinRTT = sorted[0]
	r.MaxRTT = sorted[len(sorted)-1]

	// Average
	var sum time.Duration
	for _, rtt := range rtts {
		sum += rtt
	}
	r.AvgRTT = sum / time.Duration(len(rtts))

	// Median
	n := len(sorted)
	if n%2 == 0 {
		r.MedianRTT = (sorted[n/2-1] + sorted[n/2]) / 2
	} else {
		r.MedianRTT = sorted[n/2]
	}

	// Standard deviation
	var variance float64
	avgNs := float64(r.AvgRTT.Nanoseconds())
	for _, rtt := range rtts {
		diff := float64(rtt.Nanoseconds()) - avgNs
		variance += diff * diff
	}
	variance /= float64(len(rtts))
	r.StdDev = time.Duration(int64(variance) / int64(r.AvgRTT.Nanoseconds()) * r.AvgRTT.Nanoseconds())

	// Jitter (average consecutive difference)
	if len(rtts) > 1 {
		var jitterSum time.Duration
		for i := 1; i < len(rtts); i++ {
			diff := rtts[i] - rtts[i-1]
			if diff < 0 {
				diff = -diff
			}
			jitterSum += diff
		}
		r.Jitter = jitterSum / time.Duration(len(rtts)-1)
	}
}

// Rating returns a quality rating for the RTT.
func (r *Result) Rating() string {
	if r.Successful == 0 {
		return "❌ Unreachable"
	}

	avgMs := float64(r.AvgRTT.Milliseconds())
	lossRating := ""
	if r.PacketLoss > 0 {
		lossRating = fmt.Sprintf(" (%.0f%% loss)", r.PacketLoss)
	}

	switch {
	case avgMs < 20:
		return "🟢 Excellent" + lossRating
	case avgMs < 50:
		return "🟢 Good" + lossRating
	case avgMs < 100:
		return "🟡 Fair" + lossRating
	case avgMs < 200:
		return "🟠 Slow" + lossRating
	default:
		return "🔴 Poor" + lossRating
	}
}

// Summary holds comparison summary.
type Summary struct {
	Total       int
	Reachable   int
	Unreachable int
	FastestHost string
	FastestRTT  time.Duration
	SlowestHost string
	SlowestRTT  time.Duration
	AvgRTT      time.Duration
}

// Config configures the RTT comparer.
type Config struct {
	Count       int           // Number of measurements per host
	Interval    time.Duration // Time between measurements
	Timeout     time.Duration // Connection timeout
	Concurrency int           // Parallel measurements
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Count:       5,
		Interval:    200 * time.Millisecond,
		Timeout:     5 * time.Second,
		Concurrency: 10,
	}
}

// Comparer measures and compares RTT across hosts.
type Comparer struct {
	config Config
}

// New creates a new RTT Comparer.
func New(cfg Config) *Comparer {
	if cfg.Count <= 0 {
		cfg.Count = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	return &Comparer{config: cfg}
}

// Compare measures RTT to all targets and returns results.
func (c *Comparer) Compare(ctx context.Context, targets []Target) []Result {
	results := make([]Result, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.config.Concurrency)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = c.measureTarget(ctx, tgt)
		}(i, target)
	}

	wg.Wait()
	return results
}

// measureTarget performs RTT measurements for a single target.
func (c *Comparer) measureTarget(ctx context.Context, target Target) Result {
	result := Result{
		Target:       target,
		Measurements: make([]Measurement, 0, c.config.Count),
	}

	for i := 0; i < c.config.Count; i++ {
		select {
		case <-ctx.Done():
			result.Calculate()
			return result
		default:
		}

		m := c.measureOnce(target)
		result.Measurements = append(result.Measurements, m)

		if i < c.config.Count-1 && c.config.Interval > 0 {
			select {
			case <-ctx.Done():
				result.Calculate()
				return result
			case <-time.After(c.config.Interval):
			}
		}
	}

	result.Calculate()
	return result
}

// measureOnce performs a single RTT measurement.
func (c *Comparer) measureOnce(target Target) Measurement {
	m := Measurement{
		Time: time.Now(),
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", target.Address(), c.config.Timeout)
	m.RTT = time.Since(start)

	if err != nil {
		m.Success = false
		m.Error = err
		return m
	}
	defer conn.Close()

	m.Success = true
	return m
}

// Summarize generates a summary from results.
func Summarize(results []Result) Summary {
	s := Summary{Total: len(results)}

	var totalRTT time.Duration
	var reachableCount int

	for _, r := range results {
		if r.Successful > 0 {
			s.Reachable++
			totalRTT += r.AvgRTT
			reachableCount++

			if s.FastestHost == "" || r.AvgRTT < s.FastestRTT {
				s.FastestHost = r.Target.String()
				s.FastestRTT = r.AvgRTT
			}
			if s.SlowestHost == "" || r.AvgRTT > s.SlowestRTT {
				s.SlowestHost = r.Target.String()
				s.SlowestRTT = r.AvgRTT
			}
		} else {
			s.Unreachable++
		}
	}

	if reachableCount > 0 {
		s.AvgRTT = totalRTT / time.Duration(reachableCount)
	}

	return s
}

// SortByRTT sorts results by average RTT (fastest first).
func SortByRTT(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		// Unreachable hosts go to the end
		if results[i].Successful == 0 {
			return false
		}
		if results[j].Successful == 0 {
			return true
		}
		return results[i].AvgRTT < results[j].AvgRTT
	})
}

// FormatResult formats a single result for display.
func FormatResult(r Result) string {
	if r.Successful == 0 {
		errMsg := "timeout"
		if len(r.Measurements) > 0 && r.Measurements[0].Error != nil {
			errMsg = r.Measurements[0].Error.Error()
		}
		return fmt.Sprintf("%-30s ❌ FAILED: %s", r.Target.String(), errMsg)
	}

	return fmt.Sprintf("%-30s %8.2f ms  (min: %.2f, max: %.2f, jitter: %.2f) %s",
		r.Target.String(),
		float64(r.AvgRTT.Microseconds())/1000,
		float64(r.MinRTT.Microseconds())/1000,
		float64(r.MaxRTT.Microseconds())/1000,
		float64(r.Jitter.Microseconds())/1000,
		r.Rating(),
	)
}

// FormatSummary formats summary for display.
func FormatSummary(s Summary) string {
	if s.Reachable == 0 {
		return fmt.Sprintf("Summary: %d hosts tested, all unreachable", s.Total)
	}

	return fmt.Sprintf(`Summary: %d hosts tested, %d reachable, %d unreachable
  Fastest: %s (%.2f ms)
  Slowest: %s (%.2f ms)
  Average: %.2f ms`,
		s.Total, s.Reachable, s.Unreachable,
		s.FastestHost, float64(s.FastestRTT.Microseconds())/1000,
		s.SlowestHost, float64(s.SlowestRTT.Microseconds())/1000,
		float64(s.AvgRTT.Microseconds())/1000,
	)
}

// SparkLine generates a sparkline visualization of RTT history.
func SparkLine(measurements []Measurement) string {
	if len(measurements) == 0 {
		return ""
	}

	sparks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	var rtts []time.Duration
	for _, m := range measurements {
		if m.Success {
			rtts = append(rtts, m.RTT)
		}
	}

	if len(rtts) == 0 {
		return "✗✗✗✗✗"
	}

	// Find min/max
	minRTT, maxRTT := rtts[0], rtts[0]
	for _, rtt := range rtts {
		if rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
	}

	// Build sparkline
	result := ""
	rng := maxRTT - minRTT
	for _, m := range measurements {
		if !m.Success {
			result += "✗"
			continue
		}
		idx := 0
		if rng > 0 {
			idx = int(float64(m.RTT-minRTT) / float64(rng) * float64(len(sparks)-1))
		}
		result += string(sparks[idx])
	}

	return result
}

// CommonTargets returns a set of common targets for testing.
func CommonTargets() []Target {
	return []Target{
		{Host: "8.8.8.8", Port: 53, Name: "Google DNS"},
		{Host: "1.1.1.1", Port: 53, Name: "Cloudflare DNS"},
		{Host: "208.67.222.222", Port: 53, Name: "OpenDNS"},
		{Host: "9.9.9.9", Port: 53, Name: "Quad9 DNS"},
		{Host: "google.com", Port: 443, Name: "Google"},
		{Host: "cloudflare.com", Port: 443, Name: "Cloudflare"},
		{Host: "github.com", Port: 443, Name: "GitHub"},
		{Host: "microsoft.com", Port: 443, Name: "Microsoft"},
	}
}

// ParseTarget parses a host:port string into a Target.
func ParseTarget(input string) (Target, error) {
	host, portStr, err := net.SplitHostPort(input)
	if err != nil {
		return Target{}, fmt.Errorf("invalid format, expected host:port")
	}

	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil || port <= 0 || port > 65535 {
		return Target{}, fmt.Errorf("invalid port number")
	}

	return Target{Host: host, Port: port}, nil
}
