// Package httphealth monitors HTTP endpoint health with continuous polling.
package httphealth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Status represents the health status of a single check.
type Status struct {
	URL        string        `json:"url"`
	StatusCode int           `json:"status_code"`
	Latency    time.Duration `json:"latency"`
	Healthy    bool          `json:"healthy"`
	Error      string        `json:"error,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

// EndpointStats holds accumulated statistics for a single endpoint.
type EndpointStats struct {
	URL          string        `json:"url"`
	TotalChecks  int           `json:"total_checks"`
	HealthyCount int           `json:"healthy_count"`
	FailedCount  int           `json:"failed_count"`
	Uptime       float64       `json:"uptime_pct"`
	AvgLatency   time.Duration `json:"avg_latency"`
	MinLatency   time.Duration `json:"min_latency"`
	MaxLatency   time.Duration `json:"max_latency"`
	LastStatus   *Status       `json:"last_status"`
	History      []Status      `json:"history,omitempty"`
}

// Options configures the health monitor.
type Options struct {
	URLs           []string
	Interval       time.Duration
	Timeout        time.Duration
	Method         string
	ExpectedStatus int
	MaxHistory     int
	Headers        map[string]string
}

// DefaultOptions returns sane defaults.
func DefaultOptions(urls []string) Options {
	return Options{
		URLs:           urls,
		Interval:       10 * time.Second,
		Timeout:        5 * time.Second,
		Method:         "GET",
		ExpectedStatus: 200,
		MaxHistory:     100,
	}
}

// CheckOnce performs a single health check for one URL.
func CheckOnce(ctx context.Context, url string, opts Options) Status {
	s := Status{
		URL:       url,
		Timestamp: time.Now(),
	}

	method := opts.Method
	if method == "" {
		method = "GET"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		s.Error = fmt.Sprintf("request creation failed: %v", err)
		return s
	}

	req.Header.Set("User-Agent", "nns/httphealth")
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	s.Latency = time.Since(start)

	if err != nil {
		s.Error = fmt.Sprintf("request failed: %v", err)
		return s
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	s.StatusCode = resp.StatusCode

	expected := opts.ExpectedStatus
	if expected <= 0 {
		expected = 200
	}

	s.Healthy = resp.StatusCode == expected

	return s
}

// CheckAll performs a single health check round for all URLs.
func CheckAll(ctx context.Context, opts Options) []Status {
	var wg sync.WaitGroup
	results := make([]Status, len(opts.URLs))

	for i, url := range opts.URLs {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			results[idx] = CheckOnce(ctx, u, opts)
		}(i, url)
	}

	wg.Wait()
	return results
}

// Monitor runs continuous health checks until context is cancelled.
// It calls the callback with results after each round.
func Monitor(ctx context.Context, opts Options, callback func([]Status)) {
	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	// Immediate first check
	results := CheckAll(ctx, opts)
	if callback != nil {
		callback(results)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			results := CheckAll(ctx, opts)
			if callback != nil {
				callback(results)
			}
		}
	}
}

// AccumulateStats updates endpoint statistics with new check results.
func AccumulateStats(statsMap map[string]*EndpointStats, results []Status, maxHistory int) {
	for _, r := range results {
		st, ok := statsMap[r.URL]
		if !ok {
			st = &EndpointStats{
				URL:        r.URL,
				MinLatency: r.Latency,
				MaxLatency: r.Latency,
			}
			statsMap[r.URL] = st
		}

		st.TotalChecks++
		if r.Healthy {
			st.HealthyCount++
		} else {
			st.FailedCount++
		}

		st.Uptime = float64(st.HealthyCount) / float64(st.TotalChecks) * 100.0

		if r.Latency > 0 {
			totalLatency := st.AvgLatency*time.Duration(st.TotalChecks-1) + r.Latency
			st.AvgLatency = totalLatency / time.Duration(st.TotalChecks)

			if r.Latency < st.MinLatency || st.MinLatency == 0 {
				st.MinLatency = r.Latency
			}
			if r.Latency > st.MaxLatency {
				st.MaxLatency = r.Latency
			}
		}

		st.LastStatus = &r

		if maxHistory > 0 {
			st.History = append(st.History, r)
			if len(st.History) > maxHistory {
				st.History = st.History[len(st.History)-maxHistory:]
			}
		}
	}
}

// FormatStatus returns a single-line status representation.
func FormatStatus(s Status) string {
	icon := "✓"
	if !s.Healthy {
		icon = "✗"
	}
	if s.Error != "" {
		return fmt.Sprintf("  %s %-40s  ERROR  %s", icon, truncate(s.URL, 40), truncate(s.Error, 40))
	}
	return fmt.Sprintf("  %s %-40s  %d    %s",
		icon, truncate(s.URL, 40), s.StatusCode, s.Latency.Round(time.Millisecond))
}

// FormatRound returns a formatted view of a single check round.
func FormatRound(results []Status) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  %-2s %-40s  %-6s %s\n", "", "URL", "Code", "Latency"))
	sb.WriteString(fmt.Sprintf("  %-2s %-40s  %-6s %s\n", "", "────────────────────────────────────────", "─────", "───────"))
	for _, r := range results {
		sb.WriteString(FormatStatus(r) + "\n")
	}
	return sb.String()
}

// FormatSummary returns a summary of all endpoint statistics.
func FormatSummary(statsMap map[string]*EndpointStats) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %-40s %-8s %-8s %-8s %-10s %-10s %-10s\n",
		"URL", "Checks", "Up", "Down", "Uptime%", "Avg", "Max"))
	sb.WriteString(fmt.Sprintf("  %-40s %-8s %-8s %-8s %-10s %-10s %-10s\n",
		"────────────────────────────────────────", "───────", "───────", "───────",
		"─────────", "─────────", "─────────"))

	for _, st := range statsMap {
		sb.WriteString(fmt.Sprintf("  %-40s %-8d %-8d %-8d %-10.1f %-10s %-10s\n",
			truncate(st.URL, 40),
			st.TotalChecks,
			st.HealthyCount,
			st.FailedCount,
			st.Uptime,
			st.AvgLatency.Round(time.Millisecond),
			st.MaxLatency.Round(time.Millisecond)))
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
