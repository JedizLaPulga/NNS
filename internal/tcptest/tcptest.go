// Package tcptest provides TCP connectivity testing with detailed timing metrics.
package tcptest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"time"
)

// Result represents the result of a single TCP test.
type Result struct {
	Seq           int
	Success       bool
	Error         error
	DNSTime       time.Duration // Time for DNS resolution
	ConnectTime   time.Duration // Time to establish TCP connection
	TLSTime       time.Duration // Time for TLS handshake (if applicable)
	TotalTime     time.Duration // Total round-trip time
	RemoteAddr    string        // Resolved remote address
	TLSVersion    string        // TLS version if TLS was used
	TLSCipherName string        // TLS cipher suite name
}

// Statistics holds aggregate statistics for multiple tests.
type Statistics struct {
	Sent         int
	Successful   int
	Failed       int
	MinTime      time.Duration
	MaxTime      time.Duration
	AvgTime      time.Duration
	MedianTime   time.Duration
	StdDev       time.Duration
	P95          time.Duration
	P99          time.Duration
	SuccessRate  float64
	AllTimes     []time.Duration
	AllConnTimes []time.Duration
	AvgConnTime  time.Duration
	AvgDNSTime   time.Duration
	AllDNSTimes  []time.Duration
}

// NewStatistics creates an empty Statistics struct.
func NewStatistics() *Statistics {
	return &Statistics{
		AllTimes:     make([]time.Duration, 0),
		AllConnTimes: make([]time.Duration, 0),
		AllDNSTimes:  make([]time.Duration, 0),
	}
}

// Add records a new test result.
func (s *Statistics) Add(r Result) {
	s.Sent++
	if r.Success {
		s.Successful++
		s.AllTimes = append(s.AllTimes, r.TotalTime)
		s.AllConnTimes = append(s.AllConnTimes, r.ConnectTime)
		s.AllDNSTimes = append(s.AllDNSTimes, r.DNSTime)
	} else {
		s.Failed++
	}
}

// Calculate computes aggregate statistics from collected data.
func (s *Statistics) Calculate() {
	if s.Sent == 0 {
		return
	}

	s.SuccessRate = float64(s.Successful) / float64(s.Sent) * 100

	if len(s.AllTimes) == 0 {
		return
	}

	// Sort times for percentile calculation
	sorted := make([]time.Duration, len(s.AllTimes))
	copy(sorted, s.AllTimes)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	s.MinTime = sorted[0]
	s.MaxTime = sorted[len(sorted)-1]

	// Calculate average
	var sum time.Duration
	for _, t := range sorted {
		sum += t
	}
	s.AvgTime = sum / time.Duration(len(sorted))

	// Median
	n := len(sorted)
	if n%2 == 0 {
		s.MedianTime = (sorted[n/2-1] + sorted[n/2]) / 2
	} else {
		s.MedianTime = sorted[n/2]
	}

	// Percentiles
	s.P95 = sorted[int(float64(n)*0.95)]
	s.P99 = sorted[int(float64(n)*0.99)]

	// Standard deviation
	var variance float64
	avgNs := float64(s.AvgTime.Nanoseconds())
	for _, t := range sorted {
		diff := float64(t.Nanoseconds()) - avgNs
		variance += diff * diff
	}
	variance /= float64(len(sorted))
	s.StdDev = time.Duration(sqrt(variance))

	// Average connection time
	if len(s.AllConnTimes) > 0 {
		var connSum time.Duration
		for _, t := range s.AllConnTimes {
			connSum += t
		}
		s.AvgConnTime = connSum / time.Duration(len(s.AllConnTimes))
	}

	// Average DNS time
	if len(s.AllDNSTimes) > 0 {
		var dnsSum time.Duration
		for _, t := range s.AllDNSTimes {
			dnsSum += t
		}
		s.AvgDNSTime = dnsSum / time.Duration(len(s.AllDNSTimes))
	}
}

// sqrt calculates square root for float64.
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// Tester configures and executes TCP tests.
type Tester struct {
	Host       string
	Port       int
	Count      int           // Number of tests (0 = 1)
	Interval   time.Duration // Time between tests
	Timeout    time.Duration // Connection timeout
	UseTLS     bool          // Whether to perform TLS handshake
	SkipVerify bool          // Skip TLS certificate verification
	Stats      *Statistics
}

// NewTester creates a new Tester with default settings.
func NewTester(host string, port int) *Tester {
	return &Tester{
		Host:     host,
		Port:     port,
		Count:    4,
		Interval: 1 * time.Second,
		Timeout:  10 * time.Second,
		UseTLS:   false,
		Stats:    NewStatistics(),
	}
}

// Address returns the host:port string.
func (t *Tester) Address() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// Run executes the TCP test sequence.
func (t *Tester) Run(ctx context.Context, callback func(Result)) error {
	for seq := 1; seq <= t.Count; seq++ {
		select {
		case <-ctx.Done():
			t.Stats.Calculate()
			return ctx.Err()
		default:
		}

		result := t.testOnce(seq)
		t.Stats.Add(result)
		callback(result)

		// Sleep between tests (except after last one)
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

// testOnce performs a single TCP connection test.
func (t *Tester) testOnce(seq int) Result {
	result := Result{
		Seq:     seq,
		Success: false,
	}

	totalStart := time.Now()
	address := t.Address()

	// DNS Resolution timing
	dnsStart := time.Now()
	ips, err := net.LookupIP(t.Host)
	result.DNSTime = time.Since(dnsStart)

	if err != nil {
		result.Error = fmt.Errorf("DNS resolution failed: %v", err)
		result.TotalTime = time.Since(totalStart)
		return result
	}

	if len(ips) == 0 {
		result.Error = fmt.Errorf("no IP addresses found for %s", t.Host)
		result.TotalTime = time.Since(totalStart)
		return result
	}

	// Use first IP for connection
	result.RemoteAddr = ips[0].String()

	// TCP Connection timing
	dialer := &net.Dialer{Timeout: t.Timeout}
	connStart := time.Now()
	conn, err := dialer.DialContext(context.Background(), "tcp", address)
	result.ConnectTime = time.Since(connStart)

	if err != nil {
		result.Error = fmt.Errorf("TCP connection failed: %v", err)
		result.TotalTime = time.Since(totalStart)
		return result
	}
	defer conn.Close()

	// TLS Handshake timing (if enabled)
	if t.UseTLS {
		tlsConfig := &tls.Config{
			ServerName:         t.Host,
			InsecureSkipVerify: t.SkipVerify,
		}

		tlsStart := time.Now()
		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.Handshake()
		result.TLSTime = time.Since(tlsStart)

		if err != nil {
			result.Error = fmt.Errorf("TLS handshake failed: %v", err)
			result.TotalTime = time.Since(totalStart)
			return result
		}

		// Get TLS connection state
		state := tlsConn.ConnectionState()
		result.TLSVersion = tlsVersionString(state.Version)
		result.TLSCipherName = tls.CipherSuiteName(state.CipherSuite)
	}

	result.Success = true
	result.TotalTime = time.Since(totalStart)
	return result
}

// tlsVersionString converts TLS version to string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
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

	avgMs := float64(s.AvgTime.Milliseconds())

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
