// Package conntest provides parallel connectivity testing for multiple hosts.
package conntest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Protocol represents the connection protocol.
type Protocol string

const (
	TCP Protocol = "tcp"
	TLS Protocol = "tls"
	UDP Protocol = "udp"
)

// Target represents a connectivity test target.
type Target struct {
	Host     string
	Port     int
	Protocol Protocol
	Name     string
}

func (t Target) String() string {
	if t.Name != "" {
		return t.Name
	}
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

func (t Target) Address() string {
	return net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
}

// Result represents the result of a connectivity test.
type Result struct {
	Target     Target
	Success    bool
	Latency    time.Duration
	Error      error
	TLSVersion string
	Timestamp  time.Time
}

// Config holds configuration for the connection tester.
type Config struct {
	Timeout     time.Duration
	Concurrency int
	Retries     int
}

func DefaultConfig() Config {
	return Config{Timeout: 5 * time.Second, Concurrency: 10}
}

type Tester struct {
	config Config
}

func New(cfg Config) *Tester {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	return &Tester{config: cfg}
}

func (t *Tester) Test(ctx context.Context, targets []Target) []Result {
	results := make([]Result, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, t.config.Concurrency)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, tgt Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = t.testTarget(ctx, tgt)
		}(i, target)
	}
	wg.Wait()
	return results
}

func (t *Tester) testTarget(ctx context.Context, target Target) Result {
	result := Result{Target: target, Timestamp: time.Now()}
	addr := target.Address()
	start := time.Now()

	switch target.Protocol {
	case TLS:
		host, _, _ := net.SplitHostPort(addr)
		dialer := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: t.config.Timeout},
			Config:    &tls.Config{ServerName: host, InsecureSkipVerify: true},
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		result.Latency = time.Since(start)
		if err != nil {
			result.Error = err
		} else {
			result.Success = true
			result.TLSVersion = tlsVersionString(conn.(*tls.Conn).ConnectionState().Version)
			conn.Close()
		}
	default:
		dialer := net.Dialer{Timeout: t.config.Timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		result.Latency = time.Since(start)
		if err != nil {
			result.Error = err
		} else {
			result.Success = true
			conn.Close()
		}
	}
	return result
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

func CommonTargets() []Target {
	return []Target{
		{Host: "8.8.8.8", Port: 53, Protocol: TCP, Name: "Google DNS"},
		{Host: "1.1.1.1", Port: 53, Protocol: TCP, Name: "Cloudflare DNS"},
		{Host: "google.com", Port: 443, Protocol: TLS, Name: "Google HTTPS"},
	}
}

func ParseTarget(s string) (Target, error) {
	var t Target
	t.Protocol = TCP
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return t, fmt.Errorf("invalid format: %w", err)
	}
	t.Host = host
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if port <= 0 || port > 65535 {
		return t, errors.New("invalid port")
	}
	t.Port = port
	return t, nil
}

type Summary struct {
	Total, Successful, Failed          int
	AvgLatency, MinLatency, MaxLatency time.Duration
}

func Summarize(results []Result) Summary {
	var s Summary
	s.Total = len(results)
	s.MinLatency = time.Hour
	var total time.Duration
	for _, r := range results {
		if r.Success {
			s.Successful++
			total += r.Latency
			if r.Latency < s.MinLatency {
				s.MinLatency = r.Latency
			}
			if r.Latency > s.MaxLatency {
				s.MaxLatency = r.Latency
			}
		} else {
			s.Failed++
		}
	}
	if s.Successful > 0 {
		s.AvgLatency = total / time.Duration(s.Successful)
	} else {
		s.MinLatency = 0
	}
	return s
}

func SortByLatency(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Success != results[j].Success {
			return results[i].Success
		}
		return results[i].Latency < results[j].Latency
	})
}

func FormatResult(r Result) string {
	status := "✓"
	if !r.Success {
		status = "✕"
	}
	lat := fmt.Sprintf("%.2fms", float64(r.Latency.Microseconds())/1000.0)
	if !r.Success {
		lat = "-"
	}
	extra := ""
	if r.TLSVersion != "" {
		extra = " [" + r.TLSVersion + "]"
	}
	if r.Error != nil {
		extra = fmt.Sprintf(" (%v)", r.Error)
	}
	return fmt.Sprintf("%s %-25s %10s%s", status, r.Target.String(), lat, extra)
}

func FormatSummary(s Summary) string {
	rate := 0.0
	if s.Total > 0 {
		rate = float64(s.Successful) / float64(s.Total) * 100
	}
	return fmt.Sprintf("Total: %d | OK: %d (%.1f%%) | Fail: %d | Latency: %.2f-%.2fms",
		s.Total, s.Successful, rate, s.Failed,
		float64(s.MinLatency.Microseconds())/1000.0, float64(s.MaxLatency.Microseconds())/1000.0)
}
