// Package websocket provides WebSocket connectivity testing.
package websocket

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// Result represents a single WebSocket test result.
type Result struct {
	Seq           int
	Success       bool
	Error         error
	ConnectTime   time.Duration // Time to establish WebSocket connection
	RoundTripTime time.Duration // Time for ping-pong message
	TotalTime     time.Duration
	Protocol      string // WebSocket protocol negotiated
	HTTPStatus    int    // HTTP upgrade status code
}

// Statistics holds aggregate statistics for multiple tests.
type Statistics struct {
	Sent        int
	Successful  int
	Failed      int
	MinRTT      time.Duration
	MaxRTT      time.Duration
	AvgRTT      time.Duration
	MedianRTT   time.Duration
	StdDev      time.Duration
	P95         time.Duration
	P99         time.Duration
	Jitter      time.Duration
	SuccessRate float64
	AllRTTs     []time.Duration
}

// NewStatistics creates an empty Statistics struct.
func NewStatistics() *Statistics {
	return &Statistics{
		AllRTTs: make([]time.Duration, 0),
	}
}

// Add records a new test result.
func (s *Statistics) Add(r Result) {
	s.Sent++
	if r.Success {
		s.Successful++
		s.AllRTTs = append(s.AllRTTs, r.RoundTripTime)
	} else {
		s.Failed++
	}
}

// Calculate computes aggregate statistics.
func (s *Statistics) Calculate() {
	if s.Sent == 0 {
		return
	}

	s.SuccessRate = float64(s.Successful) / float64(s.Sent) * 100

	if len(s.AllRTTs) == 0 {
		return
	}

	sorted := make([]time.Duration, len(s.AllRTTs))
	copy(sorted, s.AllRTTs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	s.MinRTT = sorted[0]
	s.MaxRTT = sorted[len(sorted)-1]

	var sum time.Duration
	for _, t := range sorted {
		sum += t
	}
	s.AvgRTT = sum / time.Duration(len(sorted))

	n := len(sorted)
	if n%2 == 0 {
		s.MedianRTT = (sorted[n/2-1] + sorted[n/2]) / 2
	} else {
		s.MedianRTT = sorted[n/2]
	}

	if n > 1 {
		p95Idx := int(float64(n) * 0.95)
		if p95Idx >= n {
			p95Idx = n - 1
		}
		s.P95 = sorted[p95Idx]

		p99Idx := int(float64(n) * 0.99)
		if p99Idx >= n {
			p99Idx = n - 1
		}
		s.P99 = sorted[p99Idx]
	} else {
		s.P95 = sorted[0]
		s.P99 = sorted[0]
	}

	var variance float64
	avgNs := float64(s.AvgRTT.Nanoseconds())
	for _, t := range sorted {
		diff := float64(t.Nanoseconds()) - avgNs
		variance += diff * diff
	}
	variance /= float64(len(sorted))
	s.StdDev = time.Duration(math.Sqrt(variance))

	// Jitter calculation (average deviation between consecutive samples)
	if len(s.AllRTTs) > 1 {
		var jitterSum time.Duration
		for i := 1; i < len(s.AllRTTs); i++ {
			diff := s.AllRTTs[i] - s.AllRTTs[i-1]
			if diff < 0 {
				diff = -diff
			}
			jitterSum += diff
		}
		s.Jitter = jitterSum / time.Duration(len(s.AllRTTs)-1)
	}
}

// Quality returns a human-readable quality assessment.
func (s *Statistics) Quality() string {
	if s.Successful == 0 {
		return "❌ Connection Failed"
	}

	if s.SuccessRate < 50 {
		return "🔴 Poor - High failure rate"
	}

	avgMs := float64(s.AvgRTT.Milliseconds())

	switch {
	case avgMs < 50:
		return "🟢 Excellent"
	case avgMs < 100:
		return "🟢 Good"
	case avgMs < 200:
		return "🟡 Fair"
	case avgMs < 500:
		return "🟠 Slow"
	default:
		return "🔴 Poor"
	}
}

// Tester configures and executes WebSocket tests.
type Tester struct {
	URL         string
	Count       int
	Interval    time.Duration
	Timeout     time.Duration
	SkipVerify  bool
	Origin      string
	MessageSize int
	Protocol    string // Sub-protocol to request
	Headers     http.Header
	Stats       *Statistics
	mu          sync.Mutex
}

// NewTester creates a new Tester with default settings.
func NewTester(url string) *Tester {
	origin := "http://localhost/"
	if strings.HasPrefix(url, "wss://") {
		origin = "https://localhost/"
	}

	return &Tester{
		URL:         url,
		Count:       4,
		Interval:    1 * time.Second,
		Timeout:     10 * time.Second,
		SkipVerify:  false,
		Origin:      origin,
		MessageSize: 32,
		Headers:     make(http.Header),
		Stats:       NewStatistics(),
	}
}

// Run executes the WebSocket test sequence.
func (t *Tester) Run(ctx context.Context, callback func(Result)) error {
	for seq := 1; seq <= t.Count; seq++ {
		select {
		case <-ctx.Done():
			t.Stats.Calculate()
			return ctx.Err()
		default:
		}

		result := t.testOnce(ctx, seq)
		t.mu.Lock()
		t.Stats.Add(result)
		t.mu.Unlock()
		callback(result)

		if seq < t.Count {
			select {
			case <-ctx.Done():
				t.Stats.Calculate()
				return ctx.Err()
			case <-time.After(t.Interval):
			}
		}
	}

	t.Stats.Calculate()
	return nil
}

// testOnce performs a single WebSocket connection test.
func (t *Tester) testOnce(ctx context.Context, seq int) Result {
	result := Result{
		Seq:     seq,
		Success: false,
	}

	totalStart := time.Now()

	config, err := websocket.NewConfig(t.URL, t.Origin)
	if err != nil {
		result.Error = fmt.Errorf("invalid URL: %w", err)
		result.TotalTime = time.Since(totalStart)
		return result
	}

	if t.Protocol != "" {
		config.Protocol = []string{t.Protocol}
	}

	for k, v := range t.Headers {
		config.Header[k] = v
	}

	if t.SkipVerify && strings.HasPrefix(t.URL, "wss://") {
		config.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Set timeout via context
	dialCtx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()

	connectStart := time.Now()
	conn, err := dialWebSocket(dialCtx, config)
	result.ConnectTime = time.Since(connectStart)

	if err != nil {
		result.Error = fmt.Errorf("connection failed: %w", err)
		result.TotalTime = time.Since(totalStart)
		return result
	}
	defer conn.Close()

	if len(conn.Config().Protocol) > 0 {
		result.Protocol = conn.Config().Protocol[0]
	}
	result.HTTPStatus = 101

	// Send ping message
	pingData := strings.Repeat("x", t.MessageSize)
	rttStart := time.Now()

	if err := websocket.Message.Send(conn, pingData); err != nil {
		result.Error = fmt.Errorf("send failed: %w", err)
		result.TotalTime = time.Since(totalStart)
		return result
	}

	var response string
	if err := websocket.Message.Receive(conn, &response); err != nil {
		if err == io.EOF {
			// Server closed after receiving - that's okay, measure up to here
			result.RoundTripTime = time.Since(rttStart)
			result.Success = true
			result.TotalTime = time.Since(totalStart)
			return result
		}
		result.Error = fmt.Errorf("receive failed: %w", err)
		result.TotalTime = time.Since(totalStart)
		return result
	}

	result.RoundTripTime = time.Since(rttStart)
	result.Success = true
	result.TotalTime = time.Since(totalStart)
	return result
}

// dialWebSocket dials a WebSocket with context support.
func dialWebSocket(ctx context.Context, config *websocket.Config) (*websocket.Conn, error) {
	type result struct {
		conn *websocket.Conn
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		// Create custom dialer with timeout
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
		}

		var netConn net.Conn
		var err error

		host := config.Location.Host
		if config.Location.Scheme == "wss" {
			tlsConfig := config.TlsConfig
			if tlsConfig == nil {
				tlsConfig = &tls.Config{}
			}
			if tlsConfig.ServerName == "" {
				hostname := host
				if idx := strings.Index(hostname, ":"); idx != -1 {
					hostname = hostname[:idx]
				}
				tlsConfig.ServerName = hostname
			}
			netConn, err = tls.DialWithDialer(dialer, "tcp", host, tlsConfig)
		} else {
			netConn, err = dialer.Dial("tcp", host)
		}

		if err != nil {
			ch <- result{nil, err}
			return
		}

		ws, err := websocket.NewClient(config, netConn)
		if err != nil {
			netConn.Close()
			ch <- result{nil, err}
			return
		}

		ch <- result{ws, nil}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// SupportedProtocols returns common WebSocket sub-protocols.
func SupportedProtocols() []string {
	return []string{
		"",
		"chat",
		"json",
		"binary",
		"graphql-ws",
		"graphql-transport-ws",
	}
}
