// Package urlcheck provides URL health monitoring.
package urlcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result represents the result of a URL check.
type Result struct {
	URL          string
	StatusCode   int
	Status       string
	ResponseTime time.Duration
	ContentSize  int64
	ContentType  string
	RedirectURL  string
	TLSVersion   string
	Error        error
	Timestamp    time.Time
}

// IsHealthy returns true if the response indicates a healthy service.
func (r *Result) IsHealthy() bool {
	return r.Error == nil && r.StatusCode >= 200 && r.StatusCode < 400
}

// Target represents a URL to monitor.
type Target struct {
	URL         string
	Name        string
	Method      string
	ExpectCode  int
	Headers     map[string]string
	FollowRedir bool
}

// Config holds configuration for the checker.
type Config struct {
	Timeout      time.Duration
	Concurrency  int
	FollowRedir  bool
	SkipTLSCheck bool
	UserAgent    string
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:     10 * time.Second,
		Concurrency: 10,
		FollowRedir: true,
		UserAgent:   "NNS/1.0 URL Checker",
	}
}

// Checker performs URL health checks.
type Checker struct {
	config Config
	client *http.Client
}

// New creates a new Checker.
func New(cfg Config) *Checker {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "NNS/1.0 URL Checker"
	}

	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: cfg.SkipTLSCheck},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	}

	var checkRedirect func(req *http.Request, via []*http.Request) error
	if !cfg.FollowRedir {
		checkRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Checker{
		config: cfg,
		client: &http.Client{Timeout: cfg.Timeout, Transport: transport, CheckRedirect: checkRedirect},
	}
}

// Check performs a single URL check.
func (c *Checker) Check(ctx context.Context, target Target) Result {
	result := Result{URL: target.URL, Timestamp: time.Now()}

	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		result.Error = fmt.Errorf("invalid URL: %w", err)
		return result
	}
	if parsedURL.Scheme == "" {
		target.URL = "https://" + target.URL
	}

	method := target.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, target.URL, nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to create request: %w", err)
		return result
	}
	req.Header.Set("User-Agent", c.config.UserAgent)
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	result.ResponseTime = time.Since(start)

	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Status = resp.Status
	result.ContentType = resp.Header.Get("Content-Type")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.RedirectURL = resp.Header.Get("Location")
	}
	if resp.TLS != nil {
		result.TLSVersion = tlsVersionString(resp.TLS.Version)
	}

	bodyData, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	result.ContentSize = int64(len(bodyData))
	return result
}

// CheckMultiple checks multiple URLs concurrently.
func (c *Checker) CheckMultiple(ctx context.Context, targets []Target) []Result {
	results := make([]Result, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.config.Concurrency)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, t Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = c.Check(ctx, t)
		}(i, target)
	}
	wg.Wait()
	return results
}

// Summary holds aggregate statistics.
type Summary struct {
	Total, Healthy, Unhealthy int
	AvgTime, MinTime, MaxTime time.Duration
	StatusDist                map[int]int
}

// Summarize generates statistics from results.
func Summarize(results []Result) Summary {
	s := Summary{Total: len(results), MinTime: time.Hour, StatusDist: make(map[int]int)}
	var totalTime time.Duration
	var count int

	for _, r := range results {
		if r.IsHealthy() {
			s.Healthy++
		} else {
			s.Unhealthy++
		}
		if r.Error == nil {
			s.StatusDist[r.StatusCode]++
			totalTime += r.ResponseTime
			count++
			if r.ResponseTime < s.MinTime {
				s.MinTime = r.ResponseTime
			}
			if r.ResponseTime > s.MaxTime {
				s.MaxTime = r.ResponseTime
			}
		}
	}
	if count > 0 {
		s.AvgTime = totalTime / time.Duration(count)
	} else {
		s.MinTime = 0
	}
	return s
}

// SortByResponseTime sorts results by response time.
func SortByResponseTime(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Error != nil && results[j].Error == nil {
			return false
		}
		if results[i].Error == nil && results[j].Error != nil {
			return true
		}
		return results[i].ResponseTime < results[j].ResponseTime
	})
}

// ParseTargets parses URL strings into targets.
func ParseTargets(urls []string) []Target {
	targets := make([]Target, len(urls))
	for i, u := range urls {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "https://" + u
		}
		targets[i] = Target{URL: u}
	}
	return targets
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// FormatResult formats a result for display.
func FormatResult(r Result) string {
	status := "✓"
	if !r.IsHealthy() {
		status = "✕"
	}
	if r.Error != nil {
		return fmt.Sprintf("%s %-50s  ERROR  %v", status, truncate(r.URL, 50), r.Error)
	}
	return fmt.Sprintf("%s %-50s  %3d  %8.2fms  %s",
		status, truncate(r.URL, 50), r.StatusCode,
		float64(r.ResponseTime.Microseconds())/1000.0, formatSize(r.ContentSize))
}

// FormatSummary formats a summary for display.
func FormatSummary(s Summary) string {
	rate := 0.0
	if s.Total > 0 {
		rate = float64(s.Healthy) / float64(s.Total) * 100
	}
	return fmt.Sprintf("Total: %d | Healthy: %d (%.1f%%) | Unhealthy: %d | Avg: %.2fms",
		s.Total, s.Healthy, rate, s.Unhealthy, float64(s.AvgTime.Microseconds())/1000.0)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func formatSize(b int64) string {
	if b >= 1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	}
	if b >= 1024 {
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	}
	return fmt.Sprintf("%dB", b)
}

// CommonEndpoints returns common endpoints for testing.
func CommonEndpoints() []Target {
	return []Target{
		{URL: "https://www.google.com", Name: "Google"},
		{URL: "https://www.github.com", Name: "GitHub"},
		{URL: "https://www.cloudflare.com", Name: "Cloudflare"},
	}
}
