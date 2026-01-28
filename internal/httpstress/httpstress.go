// Package httpstress provides HTTP load/stress testing
package httpstress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Result represents a single request result
type Result struct {
	StatusCode int
	Duration   time.Duration
	BytesRead  int64
	Error      error
	Timestamp  time.Time
}

// Stats contains aggregated test statistics
type Stats struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	TotalBytes      int64
	TotalDuration   time.Duration
	MinLatency      time.Duration
	MaxLatency      time.Duration
	AvgLatency      time.Duration
	P50Latency      time.Duration
	P90Latency      time.Duration
	P99Latency      time.Duration
	RequestsPerSec  float64
	BytesPerSec     float64
	StatusCodes     map[int]int64
	ErrorCounts     map[string]int64
	StartTime       time.Time
	EndTime         time.Time
}

// Options configures stress testing
type Options struct {
	URL           string
	Method        string
	Headers       map[string]string
	Body          string
	Concurrency   int
	TotalRequests int
	Duration      time.Duration
	RampUpTime    time.Duration
	Timeout       time.Duration
	KeepAlive     bool
	InsecureSkip  bool
}

// DefaultOptions returns sensible defaults
func DefaultOptions() Options {
	return Options{
		Method:      "GET",
		Headers:     make(map[string]string),
		Concurrency: 10,
		Timeout:     30 * time.Second,
		KeepAlive:   true,
	}
}

// Tester performs HTTP stress tests
type Tester struct {
	opts    Options
	client  *http.Client
	results []Result
	stats   Stats
	mu      sync.Mutex
	running atomic.Bool
}

// NewTester creates a new stress tester
func NewTester(opts Options) *Tester {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.Method == "" {
		opts.Method = "GET"
	}

	transport := &http.Transport{
		MaxIdleConns:        opts.Concurrency * 2,
		MaxIdleConnsPerHost: opts.Concurrency * 2,
		DisableKeepAlives:   !opts.KeepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.InsecureSkip},
	}

	return &Tester{
		opts: opts,
		client: &http.Client{
			Timeout:   opts.Timeout,
			Transport: transport,
		},
		stats: Stats{
			StatusCodes: make(map[int]int64),
			ErrorCounts: make(map[string]int64),
		},
	}
}

// ProgressCallback is called periodically with current stats
type ProgressCallback func(current, total int64, stats Stats)

// Run executes the stress test
func (t *Tester) Run(ctx context.Context, progress ProgressCallback) (*Stats, error) {
	if t.opts.URL == "" {
		return nil, fmt.Errorf("URL is required")
	}
	t.running.Store(true)
	t.stats.StartTime = time.Now()
	defer func() {
		t.stats.EndTime = time.Now()
		t.running.Store(false)
	}()

	var wg sync.WaitGroup
	requestChan := make(chan struct{}, t.opts.Concurrency*2)
	var requestCount int64

	// Determine stop condition
	useRequests := t.opts.TotalRequests > 0
	useDuration := t.opts.Duration > 0

	// Start workers
	for i := 0; i < t.opts.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			t.worker(ctx, workerID, requestChan)
		}(i)
	}

	// Request dispatcher
	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		defer close(requestChan)

		var deadline <-chan time.Time
		if useDuration {
			deadline = time.After(t.opts.Duration)
		}

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-deadline:
				return
			case <-ticker.C:
				if progress != nil {
					t.mu.Lock()
					stats := t.calculateStats()
					t.mu.Unlock()
					progress(atomic.LoadInt64(&requestCount), int64(t.opts.TotalRequests), stats)
				}
			default:
				if useRequests && atomic.LoadInt64(&requestCount) >= int64(t.opts.TotalRequests) {
					return
				}
				select {
				case requestChan <- struct{}{}:
					atomic.AddInt64(&requestCount, 1)
				case <-ctx.Done():
					return
				case <-deadline:
					return
				}
			}
		}
	}()

	<-dispatchDone
	wg.Wait()

	t.mu.Lock()
	finalStats := t.calculateStats()
	t.mu.Unlock()

	return &finalStats, nil
}

func (t *Tester) worker(ctx context.Context, id int, requests <-chan struct{}) {
	for range requests {
		select {
		case <-ctx.Done():
			return
		default:
			result := t.doRequest(ctx)
			t.mu.Lock()
			t.results = append(t.results, result)
			t.mu.Unlock()
		}
	}
}

func (t *Tester) doRequest(ctx context.Context) Result {
	start := time.Now()
	result := Result{Timestamp: start}

	var body io.Reader
	if t.opts.Body != "" {
		body = strings.NewReader(t.opts.Body)
	}

	req, err := http.NewRequestWithContext(ctx, t.opts.Method, t.opts.URL, body)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	for k, v := range t.opts.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)
	result.StatusCode = resp.StatusCode
	result.BytesRead = n
	result.Duration = time.Since(start)
	return result
}

func (t *Tester) calculateStats() Stats {
	stats := Stats{
		StatusCodes: make(map[int]int64),
		ErrorCounts: make(map[string]int64),
		StartTime:   t.stats.StartTime,
	}

	if len(t.results) == 0 {
		return stats
	}

	var durations []time.Duration
	for _, r := range t.results {
		stats.TotalRequests++
		stats.TotalBytes += r.BytesRead
		durations = append(durations, r.Duration)

		if r.Error != nil {
			stats.FailedRequests++
			errKey := summarizeError(r.Error)
			stats.ErrorCounts[errKey]++
		} else {
			stats.SuccessRequests++
			stats.StatusCodes[r.StatusCode]++
		}
	}

	// Duration stats
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	stats.MinLatency = durations[0]
	stats.MaxLatency = durations[len(durations)-1]

	var total time.Duration
	for _, d := range durations {
		total += d
	}
	stats.AvgLatency = total / time.Duration(len(durations))
	stats.TotalDuration = total

	stats.P50Latency = percentile(durations, 50)
	stats.P90Latency = percentile(durations, 90)
	stats.P99Latency = percentile(durations, 99)

	elapsed := time.Since(stats.StartTime).Seconds()
	if elapsed > 0 {
		stats.RequestsPerSec = float64(stats.TotalRequests) / elapsed
		stats.BytesPerSec = float64(stats.TotalBytes) / elapsed
	}

	return stats
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted) - 1) * p / 100
	return sorted[idx]
}

func summarizeError(err error) string {
	s := err.Error()
	if strings.Contains(s, "timeout") {
		return "timeout"
	}
	if strings.Contains(s, "connection refused") {
		return "connection_refused"
	}
	if strings.Contains(s, "no such host") {
		return "dns_error"
	}
	if len(s) > 30 {
		return s[:30]
	}
	return s
}

// Format returns formatted stats
func (s *Stats) Format() string {
	var sb strings.Builder
	sb.WriteString("HTTP Stress Test Results\n")
	sb.WriteString(strings.Repeat("─", 50) + "\n")
	sb.WriteString(fmt.Sprintf("Total Requests:     %d\n", s.TotalRequests))
	sb.WriteString(fmt.Sprintf("Successful:         %d (%.1f%%)\n", s.SuccessRequests, pct(s.SuccessRequests, s.TotalRequests)))
	sb.WriteString(fmt.Sprintf("Failed:             %d (%.1f%%)\n", s.FailedRequests, pct(s.FailedRequests, s.TotalRequests)))
	sb.WriteString(fmt.Sprintf("Requests/sec:       %.2f\n", s.RequestsPerSec))
	sb.WriteString(fmt.Sprintf("Bytes/sec:          %.2f KB\n", s.BytesPerSec/1024))
	sb.WriteString("\nLatency:\n")
	sb.WriteString(fmt.Sprintf("  Min:    %v\n", s.MinLatency.Round(time.Microsecond)))
	sb.WriteString(fmt.Sprintf("  Avg:    %v\n", s.AvgLatency.Round(time.Microsecond)))
	sb.WriteString(fmt.Sprintf("  Max:    %v\n", s.MaxLatency.Round(time.Microsecond)))
	sb.WriteString(fmt.Sprintf("  P50:    %v\n", s.P50Latency.Round(time.Microsecond)))
	sb.WriteString(fmt.Sprintf("  P90:    %v\n", s.P90Latency.Round(time.Microsecond)))
	sb.WriteString(fmt.Sprintf("  P99:    %v\n", s.P99Latency.Round(time.Microsecond)))
	if len(s.StatusCodes) > 0 {
		sb.WriteString("\nStatus Codes:\n")
		for code, count := range s.StatusCodes {
			sb.WriteString(fmt.Sprintf("  %d: %d\n", code, count))
		}
	}
	if len(s.ErrorCounts) > 0 {
		sb.WriteString("\nErrors:\n")
		for err, count := range s.ErrorCounts {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", err, count))
		}
	}
	return sb.String()
}

func pct(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

// IsRunning returns if test is active
func (t *Tester) IsRunning() bool {
	return t.running.Load()
}

// Results returns all results
func (t *Tester) Results() []Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := make([]Result, len(t.results))
	copy(r, t.results)
	return r
}
