// Package dnsperf provides DNS performance benchmarking
package dnsperf

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver represents a DNS resolver
type Resolver struct {
	Name    string
	Address string
	IPv6    bool
}

// CommonResolvers are well-known public DNS resolvers
var CommonResolvers = []Resolver{
	{Name: "Google", Address: "8.8.8.8:53"},
	{Name: "Google Secondary", Address: "8.8.4.4:53"},
	{Name: "Cloudflare", Address: "1.1.1.1:53"},
	{Name: "Cloudflare Secondary", Address: "1.0.0.1:53"},
	{Name: "Quad9", Address: "9.9.9.9:53"},
	{Name: "OpenDNS", Address: "208.67.222.222:53"},
	{Name: "AdGuard", Address: "94.140.14.14:53"},
}

// Result contains benchmark results for a single resolver
type Result struct {
	Resolver   Resolver
	Queries    int
	Successful int
	Failed     int
	MinLatency time.Duration
	MaxLatency time.Duration
	AvgLatency time.Duration
	P50Latency time.Duration
	P90Latency time.Duration
	P99Latency time.Duration
	Latencies  []time.Duration
	ErrorRate  float64
	QPS        float64 // queries per second
}

// BenchmarkResult contains full benchmark results
type BenchmarkResult struct {
	Domain    string
	QueryType string
	Results   []Result
	Best      *Result
	Worst     *Result
	StartTime time.Time
	Duration  time.Duration
}

// Options configures DNS benchmarking
type Options struct {
	Resolvers   []Resolver
	QueryCount  int
	Concurrency int
	Timeout     time.Duration
	QueryType   string // A, AAAA, MX, etc.
}

// DefaultOptions returns sensible defaults
func DefaultOptions() Options {
	return Options{
		Resolvers:   CommonResolvers[:4], // Google + Cloudflare
		QueryCount:  10,
		Concurrency: 5,
		Timeout:     5 * time.Second,
		QueryType:   "A",
	}
}

// Benchmark performs DNS performance benchmark
type Benchmark struct {
	opts Options
}

// NewBenchmark creates a new DNS benchmark
func NewBenchmark(opts Options) *Benchmark {
	if opts.QueryCount <= 0 {
		opts.QueryCount = 10
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 5
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.QueryType == "" {
		opts.QueryType = "A"
	}
	if len(opts.Resolvers) == 0 {
		opts.Resolvers = CommonResolvers[:4]
	}
	return &Benchmark{opts: opts}
}

// Run performs the benchmark
func (b *Benchmark) Run(ctx context.Context, domain string) (*BenchmarkResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	startTime := time.Now()
	result := &BenchmarkResult{
		Domain:    domain,
		QueryType: b.opts.QueryType,
		StartTime: startTime,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, resolver := range b.opts.Resolvers {
		wg.Add(1)
		go func(r Resolver) {
			defer wg.Done()
			res := b.benchmarkResolver(ctx, r, domain)
			mu.Lock()
			result.Results = append(result.Results, res)
			mu.Unlock()
		}(resolver)
	}

	wg.Wait()
	result.Duration = time.Since(startTime)

	// Sort by average latency
	sort.Slice(result.Results, func(i, j int) bool {
		return result.Results[i].AvgLatency < result.Results[j].AvgLatency
	})

	if len(result.Results) > 0 {
		result.Best = &result.Results[0]
		result.Worst = &result.Results[len(result.Results)-1]
	}

	return result, nil
}

func (b *Benchmark) benchmarkResolver(ctx context.Context, resolver Resolver, domain string) Result {
	result := Result{
		Resolver: resolver,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, b.opts.Concurrency)

	for i := 0; i < b.opts.QueryCount; i++ {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-semaphore }()

			latency, err := b.query(ctx, resolver, domain)

			mu.Lock()
			result.Queries++
			if err != nil {
				result.Failed++
			} else {
				result.Successful++
				result.Latencies = append(result.Latencies, latency)
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Calculate statistics
	if len(result.Latencies) > 0 {
		sort.Slice(result.Latencies, func(i, j int) bool {
			return result.Latencies[i] < result.Latencies[j]
		})

		result.MinLatency = result.Latencies[0]
		result.MaxLatency = result.Latencies[len(result.Latencies)-1]

		var total time.Duration
		for _, l := range result.Latencies {
			total += l
		}
		result.AvgLatency = total / time.Duration(len(result.Latencies))

		result.P50Latency = percentile(result.Latencies, 50)
		result.P90Latency = percentile(result.Latencies, 90)
		result.P99Latency = percentile(result.Latencies, 99)
	}

	if result.Queries > 0 {
		result.ErrorRate = float64(result.Failed) / float64(result.Queries) * 100
		if len(result.Latencies) > 0 {
			totalTime := result.AvgLatency * time.Duration(len(result.Latencies))
			if totalTime > 0 {
				result.QPS = float64(result.Successful) / totalTime.Seconds()
			}
		}
	}

	return result
}

func (b *Benchmark) query(ctx context.Context, resolver Resolver, domain string) (time.Duration, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: b.opts.Timeout}
			return d.DialContext(ctx, "udp", resolver.Address)
		},
	}

	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, b.opts.Timeout)
	defer cancel()

	var err error
	switch b.opts.QueryType {
	case "A", "AAAA":
		_, err = r.LookupIP(ctx, "ip", domain)
	case "MX":
		_, err = r.LookupMX(ctx, domain)
	case "TXT":
		_, err = r.LookupTXT(ctx, domain)
	case "NS":
		_, err = r.LookupNS(ctx, domain)
	case "CNAME":
		_, err = r.LookupCNAME(ctx, domain)
	default:
		_, err = r.LookupIP(ctx, "ip", domain)
	}

	return time.Since(start), err
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted) - 1) * p / 100
	return sorted[idx]
}

// Format returns formatted benchmark results
func (r *BenchmarkResult) Format() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("DNS Performance Benchmark: %s (%s)\n", r.Domain, r.QueryType))
	sb.WriteString(strings.Repeat("─", 80) + "\n\n")

	// Results table
	sb.WriteString(fmt.Sprintf("%-20s %10s %10s %10s %10s %8s\n",
		"Resolver", "Avg", "Min", "Max", "P99", "Error%"))
	sb.WriteString(strings.Repeat("─", 80) + "\n")

	for _, res := range r.Results {
		indicator := " "
		if r.Best != nil && res.Resolver.Address == r.Best.Resolver.Address {
			indicator = "★"
		}

		sb.WriteString(fmt.Sprintf("%s%-19s %10v %10v %10v %10v %7.1f%%\n",
			indicator,
			res.Resolver.Name,
			res.AvgLatency.Round(100*time.Microsecond),
			res.MinLatency.Round(100*time.Microsecond),
			res.MaxLatency.Round(100*time.Microsecond),
			res.P99Latency.Round(100*time.Microsecond),
			res.ErrorRate,
		))
	}

	sb.WriteString(strings.Repeat("─", 80) + "\n")

	// Summary
	if r.Best != nil {
		sb.WriteString(fmt.Sprintf("\n★ Fastest: %s (%v avg)\n",
			r.Best.Resolver.Name, r.Best.AvgLatency.Round(time.Millisecond)))
	}

	sb.WriteString(fmt.Sprintf("\nTotal time: %v\n", r.Duration.Round(time.Millisecond)))

	return sb.String()
}

// FormatCompact returns compact formatted results
func (r *BenchmarkResult) FormatCompact() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DNS Benchmark: %s\n", r.Domain))
	for i, res := range r.Results {
		rank := fmt.Sprintf("%d.", i+1)
		sb.WriteString(fmt.Sprintf("  %s %s: %v\n", rank, res.Resolver.Name, res.AvgLatency.Round(time.Millisecond)))
	}
	return sb.String()
}

// GetRanking returns resolvers ranked by performance
func (r *BenchmarkResult) GetRanking() []string {
	ranking := make([]string, len(r.Results))
	for i, res := range r.Results {
		ranking[i] = res.Resolver.Name
	}
	return ranking
}

// CompareResolvers compares two benchmark results
func CompareResolvers(a, b *Result) string {
	diff := b.AvgLatency - a.AvgLatency
	pctDiff := float64(diff) / float64(a.AvgLatency) * 100

	if diff > 0 {
		return fmt.Sprintf("%s is %.1f%% faster than %s",
			a.Resolver.Name, pctDiff, b.Resolver.Name)
	}
	return fmt.Sprintf("%s is %.1f%% faster than %s",
		b.Resolver.Name, -pctDiff, a.Resolver.Name)
}
