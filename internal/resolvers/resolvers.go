// Package resolvers provides DNS resolver comparison and recommendation.
package resolvers

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver represents a DNS resolver with metadata.
type Resolver struct {
	Name        string
	Address     string
	Provider    string
	Features    []string
	Privacy     string
	DNSSEC      bool
	DoH         bool
	DoT         bool
	Filtering   string
	Description string
}

// PublicResolvers contains well-known public DNS resolvers.
var PublicResolvers = []Resolver{
	{Name: "Google Primary", Address: "8.8.8.8:53", Provider: "Google", Privacy: "logging", DNSSEC: true},
	{Name: "Google Secondary", Address: "8.8.4.4:53", Provider: "Google", Privacy: "logging", DNSSEC: true},
	{Name: "Cloudflare Primary", Address: "1.1.1.1:53", Provider: "Cloudflare", Privacy: "no-logging", DNSSEC: true},
	{Name: "Cloudflare Secondary", Address: "1.0.0.1:53", Provider: "Cloudflare", Privacy: "no-logging", DNSSEC: true},
	{Name: "Quad9", Address: "9.9.9.9:53", Provider: "Quad9", Privacy: "no-logging", Filtering: "malware", DNSSEC: true},
	{Name: "OpenDNS", Address: "208.67.222.222:53", Provider: "Cisco", Privacy: "logging", Filtering: "phishing"},
	{Name: "AdGuard", Address: "94.140.14.14:53", Provider: "AdGuard", Privacy: "no-logging", Filtering: "ads"},
}

// TestResult contains performance test results for a resolver.
type TestResult struct {
	Resolver    Resolver
	Reachable   bool
	MinLatency  time.Duration
	MaxLatency  time.Duration
	AvgLatency  time.Duration
	SuccessRate float64
	Queries     int
	Successful  int
	Failed      int
	Latencies   []time.Duration
	ResolvedIP  string
	Score       float64
	Error       string
}

// CompareResult contains comparison results.
type CompareResult struct {
	TestDomain   string
	QueryCount   int
	Results      []TestResult
	SystemDNS    *TestResult
	Recommended  *TestResult
	FastestSpeed *TestResult
	BestPrivacy  *TestResult
	StartTime    time.Time
	Duration     time.Duration
}

// Config holds comparison configuration.
type Config struct {
	Resolvers     []Resolver
	QueryCount    int
	Timeout       time.Duration
	Concurrency   int
	TestDomain    string
	IncludeSystem bool
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Resolvers:     PublicResolvers[:4],
		QueryCount:    5,
		Timeout:       5 * time.Second,
		Concurrency:   4,
		TestDomain:    "google.com",
		IncludeSystem: true,
	}
}

// Comparator compares DNS resolvers.
type Comparator struct {
	config Config
}

// New creates a new resolver comparator.
func New(cfg Config) *Comparator {
	if cfg.QueryCount <= 0 {
		cfg.QueryCount = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if len(cfg.Resolvers) == 0 {
		cfg.Resolvers = PublicResolvers[:4]
	}
	return &Comparator{config: cfg}
}

// Compare tests all configured resolvers.
func (c *Comparator) Compare(ctx context.Context) (*CompareResult, error) {
	result := &CompareResult{
		TestDomain: c.config.TestDomain,
		QueryCount: c.config.QueryCount,
		StartTime:  time.Now(),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, resolver := range c.config.Resolvers {
		wg.Add(1)
		go func(r Resolver) {
			defer wg.Done()
			testResult := c.testResolver(ctx, r)
			mu.Lock()
			result.Results = append(result.Results, testResult)
			mu.Unlock()
		}(resolver)
	}

	if c.config.IncludeSystem {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sysRes := Resolver{Name: "System DNS", Address: "system", Provider: "System"}
			testResult := c.testSystemResolver(ctx, sysRes)
			mu.Lock()
			result.SystemDNS = &testResult
			result.Results = append(result.Results, testResult)
			mu.Unlock()
		}()
	}

	wg.Wait()
	result.Duration = time.Since(result.StartTime)

	sort.Slice(result.Results, func(i, j int) bool {
		return result.Results[i].Score < result.Results[j].Score
	})

	c.findRecommendations(result)
	return result, nil
}

func (c *Comparator) testResolver(ctx context.Context, resolver Resolver) TestResult {
	result := TestResult{Resolver: resolver, Queries: c.config.QueryCount}

	for i := 0; i < c.config.QueryCount; i++ {
		latency, ip, err := c.queryResolver(ctx, resolver.Address, c.config.TestDomain)
		if err != nil {
			result.Failed++
			result.Error = err.Error()
		} else {
			result.Successful++
			result.Latencies = append(result.Latencies, latency)
			result.ResolvedIP = ip
		}
	}

	c.calculateStats(&result)
	return result
}

func (c *Comparator) testSystemResolver(ctx context.Context, resolver Resolver) TestResult {
	result := TestResult{Resolver: resolver, Queries: c.config.QueryCount}

	for i := 0; i < c.config.QueryCount; i++ {
		start := time.Now()
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", c.config.TestDomain)
		latency := time.Since(start)

		if err != nil {
			result.Failed++
		} else {
			result.Successful++
			result.Latencies = append(result.Latencies, latency)
			if len(ips) > 0 {
				result.ResolvedIP = ips[0].String()
			}
		}
	}

	c.calculateStats(&result)
	return result
}

func (c *Comparator) queryResolver(ctx context.Context, address, domain string) (time.Duration, string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: c.config.Timeout}
			return d.DialContext(ctx, "udp", address)
		},
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	start := time.Now()
	ips, err := r.LookupIP(ctx, "ip4", domain)
	latency := time.Since(start)

	if err != nil {
		return latency, "", err
	}
	if len(ips) == 0 {
		return latency, "", fmt.Errorf("no IP returned")
	}
	return latency, ips[0].String(), nil
}

func (c *Comparator) calculateStats(result *TestResult) {
	if len(result.Latencies) == 0 {
		result.Score = 999999
		return
	}
	result.Reachable = true

	sorted := make([]time.Duration, len(result.Latencies))
	copy(sorted, result.Latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	result.MinLatency = sorted[0]
	result.MaxLatency = sorted[len(sorted)-1]

	var total time.Duration
	for _, l := range sorted {
		total += l
	}
	result.AvgLatency = total / time.Duration(len(sorted))
	result.SuccessRate = float64(result.Successful) / float64(result.Queries) * 100
	result.Score = float64(result.AvgLatency.Milliseconds()) + (100-result.SuccessRate)*10
}

func (c *Comparator) findRecommendations(result *CompareResult) {
	for i := range result.Results {
		if result.Results[i].Reachable {
			result.Recommended = &result.Results[i]
			break
		}
	}

	for i := range result.Results {
		r := &result.Results[i]
		if r.Reachable && (result.FastestSpeed == nil || r.MinLatency < result.FastestSpeed.MinLatency) {
			result.FastestSpeed = r
		}
		if r.Reachable && r.Resolver.Privacy == "no-logging" {
			if result.BestPrivacy == nil || r.Score < result.BestPrivacy.Score {
				result.BestPrivacy = r
			}
		}
	}
}

// Format returns formatted comparison results.
func (r *CompareResult) Format() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DNS Resolver Comparison: %s\n", r.TestDomain))
	sb.WriteString(strings.Repeat("─", 80) + "\n\n")

	sb.WriteString(fmt.Sprintf("%-20s %10s %10s %10s %8s\n", "Resolver", "Avg", "Min", "Max", "Success"))
	sb.WriteString(strings.Repeat("─", 80) + "\n")

	for _, res := range r.Results {
		indicator := " "
		if r.Recommended != nil && res.Resolver.Address == r.Recommended.Resolver.Address {
			indicator = "★"
		}
		if res.Reachable {
			sb.WriteString(fmt.Sprintf("%s%-19s %10v %10v %10v %7.0f%%\n",
				indicator, res.Resolver.Name,
				res.AvgLatency.Round(100*time.Microsecond),
				res.MinLatency.Round(100*time.Microsecond),
				res.MaxLatency.Round(100*time.Microsecond),
				res.SuccessRate))
		} else {
			sb.WriteString(fmt.Sprintf(" %-19s %10s %10s %10s %7s\n", res.Resolver.Name, "--", "--", "--", "FAIL"))
		}
	}

	sb.WriteString(strings.Repeat("─", 80) + "\n\n")
	if r.Recommended != nil {
		sb.WriteString(fmt.Sprintf("★ Recommended: %s (%v avg)\n", r.Recommended.Resolver.Name, r.Recommended.AvgLatency.Round(time.Millisecond)))
	}
	if r.BestPrivacy != nil {
		sb.WriteString(fmt.Sprintf("🔒 Best Privacy: %s\n", r.BestPrivacy.Resolver.Name))
	}
	return sb.String()
}

// GetByCategory returns resolvers filtered by category.
func GetByCategory(category string) []Resolver {
	var result []Resolver

	for _, r := range PublicResolvers {
		switch category {
		case "privacy":
			if r.Privacy == "no-logging" {
				result = append(result, r)
			}
		case "security":
			if r.Filtering == "malware" {
				result = append(result, r)
			}
		case "family":
			if r.Filtering == "family" {
				result = append(result, r)
			}
		case "adblock":
			if r.Filtering == "ads" {
				result = append(result, r)
			}
		case "speed":
			if r.Provider == "Google" || r.Provider == "Cloudflare" {
				result = append(result, r)
			}
		}
	}

	return result
}
