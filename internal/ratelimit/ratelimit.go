// Package ratelimit probes HTTP endpoints to discover rate limiting policies.
package ratelimit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Policy represents discovered rate limit information from a single response.
type Policy struct {
	Limit     int    `json:"limit"`
	Remaining int    `json:"remaining"`
	Reset     int64  `json:"reset"`
	Window    string `json:"window"`
	RetryStr  string `json:"retry_after,omitempty"`
}

// ProbeResult holds the result of probing a single request.
type ProbeResult struct {
	RequestNum int           `json:"request_num"`
	StatusCode int           `json:"status_code"`
	Latency    time.Duration `json:"latency"`
	Policy     *Policy       `json:"policy,omitempty"`
	Limited    bool          `json:"limited"`
	Error      string        `json:"error,omitempty"`
}

// Summary is the final aggregate of a rate limit probe session.
type Summary struct {
	URL             string        `json:"url"`
	TotalRequests   int           `json:"total_requests"`
	SuccessCount    int           `json:"success_count"`
	LimitedCount    int           `json:"limited_count"`
	ErrorCount      int           `json:"error_count"`
	FirstLimitedAt  int           `json:"first_limited_at"`
	DetectedLimit   int           `json:"detected_limit"`
	DetectedWindow  string        `json:"detected_window"`
	AvgLatency      time.Duration `json:"avg_latency"`
	MinLatency      time.Duration `json:"min_latency"`
	MaxLatency      time.Duration `json:"max_latency"`
	HasRateLimiting bool          `json:"has_rate_limiting"`
	Headers         []string      `json:"headers_found"`
	Results         []ProbeResult `json:"results"`
}

// Options configures the rate limit probe behavior.
type Options struct {
	URL        string
	Method     string
	Count      int
	Delay      time.Duration
	Timeout    time.Duration
	Headers    map[string]string
	Concurrent int
}

// DefaultOptions returns sane defaults for probing.
func DefaultOptions(url string) Options {
	return Options{
		URL:        url,
		Method:     "GET",
		Count:      30,
		Delay:      100 * time.Millisecond,
		Timeout:    10 * time.Second,
		Concurrent: 1,
	}
}

// Probe sends repeated requests to discover rate limiting behavior.
func Probe(ctx context.Context, opts Options) Summary {
	s := Summary{
		URL:     opts.URL,
		Results: make([]ProbeResult, 0, opts.Count),
	}

	client := &http.Client{Timeout: opts.Timeout}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, max(opts.Concurrent, 1))

	var totalLatency time.Duration

	for i := 1; i <= opts.Count; i++ {
		select {
		case <-ctx.Done():
			s.TotalRequests = i - 1
			finalize(&s, totalLatency)
			return s
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(num int) {
			defer wg.Done()
			defer func() { <-sem }()

			r := probeOne(ctx, client, opts, num)

			mu.Lock()
			s.Results = append(s.Results, r)
			totalLatency += r.Latency
			if r.Error != "" {
				s.ErrorCount++
			} else if r.Limited {
				s.LimitedCount++
				if s.FirstLimitedAt == 0 {
					s.FirstLimitedAt = num
				}
			} else {
				s.SuccessCount++
			}
			mu.Unlock()
		}(i)

		if opts.Delay > 0 && opts.Concurrent <= 1 {
			time.Sleep(opts.Delay)
		}
	}

	wg.Wait()
	s.TotalRequests = opts.Count
	finalize(&s, totalLatency)
	return s
}

func probeOne(ctx context.Context, client *http.Client, opts Options, num int) ProbeResult {
	r := ProbeResult{RequestNum: num}

	req, err := http.NewRequestWithContext(ctx, opts.Method, opts.URL, nil)
	if err != nil {
		r.Error = fmt.Sprintf("request creation failed: %v", err)
		return r
	}

	req.Header.Set("User-Agent", "nns/ratelimit-probe")
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	r.Latency = time.Since(start)

	if err != nil {
		r.Error = fmt.Sprintf("request failed: %v", err)
		return r
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	r.StatusCode = resp.StatusCode
	r.Limited = resp.StatusCode == 429

	p := parseRateLimitHeaders(resp)
	if p != nil {
		r.Policy = p
	}

	if resp.StatusCode == 429 {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if r.Policy == nil {
				r.Policy = &Policy{}
			}
			r.Policy.RetryStr = ra
		}
	}

	return r
}

func parseRateLimitHeaders(resp *http.Response) *Policy {
	p := &Policy{}
	found := false

	// Standard headers
	for _, prefix := range []string{"X-RateLimit", "X-Rate-Limit", "RateLimit"} {
		if v := resp.Header.Get(prefix + "-Limit"); v != "" {
			p.Limit, _ = strconv.Atoi(strings.TrimSpace(v))
			found = true
		}
		if v := resp.Header.Get(prefix + "-Remaining"); v != "" {
			p.Remaining, _ = strconv.Atoi(strings.TrimSpace(v))
			found = true
		}
		if v := resp.Header.Get(prefix + "-Reset"); v != "" {
			p.Reset, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			found = true
		}
		if v := resp.Header.Get(prefix + "-Window"); v != "" {
			p.Window = strings.TrimSpace(v)
			found = true
		}
	}

	if !found {
		return nil
	}
	return p
}

func finalize(s *Summary, totalLatency time.Duration) {
	if len(s.Results) == 0 {
		return
	}

	s.MinLatency = s.Results[0].Latency
	s.MaxLatency = s.Results[0].Latency

	hdrs := map[string]bool{}
	for _, r := range s.Results {
		if r.Latency < s.MinLatency {
			s.MinLatency = r.Latency
		}
		if r.Latency > s.MaxLatency {
			s.MaxLatency = r.Latency
		}
		if r.Policy != nil {
			if r.Policy.Limit > 0 {
				s.DetectedLimit = r.Policy.Limit
				hdrs["X-RateLimit-Limit"] = true
			}
			if r.Policy.Remaining >= 0 && r.Policy.Limit > 0 {
				hdrs["X-RateLimit-Remaining"] = true
			}
			if r.Policy.Reset > 0 {
				hdrs["X-RateLimit-Reset"] = true
			}
			if r.Policy.Window != "" {
				s.DetectedWindow = r.Policy.Window
				hdrs["X-RateLimit-Window"] = true
			}
			if r.Policy.RetryStr != "" {
				hdrs["Retry-After"] = true
			}
		}
	}

	s.HasRateLimiting = s.LimitedCount > 0 || s.DetectedLimit > 0
	if s.TotalRequests > 0 {
		s.AvgLatency = totalLatency / time.Duration(s.TotalRequests)
	}
	for h := range hdrs {
		s.Headers = append(s.Headers, h)
	}
}

// FindRateLimitHeaders returns all rate-limit-related headers from a response.
func FindRateLimitHeaders(resp *http.Response) map[string]string {
	found := make(map[string]string)
	for key, vals := range resp.Header {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "ratelimit") ||
			strings.Contains(lower, "rate-limit") ||
			strings.Contains(lower, "retry-after") ||
			strings.Contains(lower, "x-retry") {
			found[key] = strings.Join(vals, ", ")
		}
	}
	return found
}

// FormatSummary returns a human-readable summary of the probe results.
func FormatSummary(s Summary) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  URL:             %s\n", s.URL))
	sb.WriteString(fmt.Sprintf("  Total Requests:  %d\n", s.TotalRequests))
	sb.WriteString(fmt.Sprintf("  Successful:      %d\n", s.SuccessCount))
	sb.WriteString(fmt.Sprintf("  Rate Limited:    %d\n", s.LimitedCount))
	sb.WriteString(fmt.Sprintf("  Errors:          %d\n", s.ErrorCount))
	sb.WriteString(fmt.Sprintf("  Avg Latency:     %s\n", s.AvgLatency.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("  Min Latency:     %s\n", s.MinLatency.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("  Max Latency:     %s\n", s.MaxLatency.Round(time.Millisecond)))

	sb.WriteString("\n")
	if s.HasRateLimiting {
		sb.WriteString("  ⚠ Rate Limiting DETECTED\n")
		if s.DetectedLimit > 0 {
			sb.WriteString(fmt.Sprintf("  Limit:           %d requests", s.DetectedLimit))
			if s.DetectedWindow != "" {
				sb.WriteString(fmt.Sprintf(" / %s", s.DetectedWindow))
			}
			sb.WriteString("\n")
		}
		if s.FirstLimitedAt > 0 {
			sb.WriteString(fmt.Sprintf("  First 429 at:    request #%d\n", s.FirstLimitedAt))
		}
	} else {
		sb.WriteString("  ✓ No rate limiting detected\n")
	}

	if len(s.Headers) > 0 {
		sb.WriteString(fmt.Sprintf("\n  Headers Found:   %s\n", strings.Join(s.Headers, ", ")))
	}

	return sb.String()
}

// FormatResults returns a tabulated view of individual probe results.
func FormatResults(results []ProbeResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  %-6s %-6s %-10s %-10s %-10s %s\n",
		"#", "Code", "Latency", "Limit", "Remaining", "Status"))
	sb.WriteString(fmt.Sprintf("  %-6s %-6s %-10s %-10s %-10s %s\n",
		"─────", "─────", "─────────", "─────────", "─────────", "──────"))

	for _, r := range results {
		limitStr := "-"
		remStr := "-"
		if r.Policy != nil {
			if r.Policy.Limit > 0 {
				limitStr = strconv.Itoa(r.Policy.Limit)
			}
			remStr = strconv.Itoa(r.Policy.Remaining)
		}

		status := "✓ OK"
		if r.Error != "" {
			status = "✗ " + truncate(r.Error, 30)
		} else if r.Limited {
			status = "⚠ 429 Rate Limited"
		}

		sb.WriteString(fmt.Sprintf("  %-6d %-6d %-10s %-10s %-10s %s\n",
			r.RequestNum, r.StatusCode, r.Latency.Round(time.Millisecond),
			limitStr, remStr, status))
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
