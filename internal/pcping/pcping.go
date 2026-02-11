// Package pcping provides protocol-aware ping using TCP, UDP, HTTP, and DNS probes.
package pcping

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
	"time"
)

// Protocol identifies the probe type.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoHTTP Protocol = "http"
	ProtoDNS  Protocol = "dns"
)

// ProbeResult represents the result of a single probe.
type ProbeResult struct {
	Seq      int
	Success  bool
	Error    error
	RTT      time.Duration
	Protocol Protocol
	Addr     string
	Detail   string // Protocol-specific detail (HTTP status, DNS response, etc.)
}

// Statistics holds aggregate statistics for probe results.
type Statistics struct {
	Protocol    Protocol
	Sent        int
	Received    int
	Lost        int
	LossPercent float64
	MinRTT      time.Duration
	MaxRTT      time.Duration
	AvgRTT      time.Duration
	MedianRTT   time.Duration
	StdDev      time.Duration
	P95         time.Duration
	P99         time.Duration
	AllRTTs     []time.Duration
}

// NewStatistics creates an empty Statistics struct.
func NewStatistics(proto Protocol) *Statistics {
	return &Statistics{
		Protocol: proto,
		AllRTTs:  make([]time.Duration, 0),
	}
}

// Add records a probe result.
func (s *Statistics) Add(r ProbeResult) {
	s.Sent++
	if r.Success {
		s.Received++
		s.AllRTTs = append(s.AllRTTs, r.RTT)
	} else {
		s.Lost++
	}
}

// Calculate computes aggregate statistics.
func (s *Statistics) Calculate() {
	if s.Sent == 0 {
		return
	}

	s.LossPercent = float64(s.Lost) / float64(s.Sent) * 100

	if len(s.AllRTTs) == 0 {
		return
	}

	sorted := make([]time.Duration, len(s.AllRTTs))
	copy(sorted, s.AllRTTs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	s.MinRTT = sorted[0]
	s.MaxRTT = sorted[len(sorted)-1]

	var sum time.Duration
	for _, rtt := range sorted {
		sum += rtt
	}
	s.AvgRTT = sum / time.Duration(len(sorted))

	// Median
	n := len(sorted)
	if n%2 == 0 {
		s.MedianRTT = (sorted[n/2-1] + sorted[n/2]) / 2
	} else {
		s.MedianRTT = sorted[n/2]
	}

	// Percentiles
	if n > 1 {
		p95idx := int(float64(n) * 0.95)
		if p95idx >= n {
			p95idx = n - 1
		}
		s.P95 = sorted[p95idx]

		p99idx := int(float64(n) * 0.99)
		if p99idx >= n {
			p99idx = n - 1
		}
		s.P99 = sorted[p99idx]
	} else {
		s.P95 = sorted[0]
		s.P99 = sorted[0]
	}

	// Standard deviation
	var variance float64
	avgNs := float64(s.AvgRTT.Nanoseconds())
	for _, rtt := range sorted {
		diff := float64(rtt.Nanoseconds()) - avgNs
		variance += diff * diff
	}
	variance /= float64(len(sorted))
	s.StdDev = time.Duration(math.Sqrt(variance))
}

// Quality returns a human-readable quality string.
func (s *Statistics) Quality() string {
	if s.Received == 0 {
		return "❌ No response"
	}

	if s.LossPercent > 50 {
		return "🔴 Poor - High packet loss"
	}

	avgMs := float64(s.AvgRTT.Milliseconds())
	switch {
	case avgMs < 20:
		return "🟢 Excellent"
	case avgMs < 50:
		return "🟢 Good"
	case avgMs < 100:
		return "🟡 Fair"
	case avgMs < 300:
		return "🟠 Slow"
	default:
		return "🔴 Poor"
	}
}

// Options configures the protocol-aware pinger.
type Options struct {
	Host     string
	Port     int
	Protocol Protocol
	Count    int
	Interval time.Duration
	Timeout  time.Duration
	UseTLS   bool
	HTTPPath string // Path for HTTP probes
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Port:     80,
		Protocol: ProtoTCP,
		Count:    5,
		Interval: 1 * time.Second,
		Timeout:  5 * time.Second,
		HTTPPath: "/",
	}
}

// Pinger executes protocol-aware pings.
type Pinger struct {
	opts  Options
	Stats *Statistics
}

// NewPinger creates a new pinger.
func NewPinger(opts Options) *Pinger {
	if opts.Count <= 0 {
		opts.Count = 5
	}
	if opts.Interval <= 0 {
		opts.Interval = 1 * time.Second
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Port <= 0 {
		switch opts.Protocol {
		case ProtoHTTP:
			opts.Port = 80
		case ProtoDNS:
			opts.Port = 53
		default:
			opts.Port = 80
		}
	}
	if opts.HTTPPath == "" {
		opts.HTTPPath = "/"
	}
	return &Pinger{
		opts:  opts,
		Stats: NewStatistics(opts.Protocol),
	}
}

// Port returns the resolved port being used.
func (p *Pinger) Port() int {
	return p.opts.Port
}

// Run executes the probe sequence, calling the callback for each result.
func (p *Pinger) Run(ctx context.Context, callback func(ProbeResult)) error {
	for seq := 1; seq <= p.opts.Count; seq++ {
		select {
		case <-ctx.Done():
			p.Stats.Calculate()
			return ctx.Err()
		default:
		}

		var result ProbeResult
		switch p.opts.Protocol {
		case ProtoTCP:
			result = p.probeTCP(seq)
		case ProtoUDP:
			result = p.probeUDP(seq)
		case ProtoHTTP:
			result = p.probeHTTP(seq)
		case ProtoDNS:
			result = p.probeDNS(seq)
		default:
			result = ProbeResult{
				Seq:      seq,
				Protocol: p.opts.Protocol,
				Error:    fmt.Errorf("unsupported protocol: %s", p.opts.Protocol),
			}
		}

		p.Stats.Add(result)
		callback(result)

		if seq < p.opts.Count {
			select {
			case <-ctx.Done():
				p.Stats.Calculate()
				return ctx.Err()
			case <-time.After(p.opts.Interval):
			}
		}
	}

	p.Stats.Calculate()
	return nil
}

// probeTCP performs a TCP connect probe.
func (p *Pinger) probeTCP(seq int) ProbeResult {
	result := ProbeResult{
		Seq:      seq,
		Protocol: ProtoTCP,
	}

	addr := fmt.Sprintf("%s:%d", p.opts.Host, p.opts.Port)
	start := time.Now()

	dialer := &net.Dialer{Timeout: p.opts.Timeout}
	conn, err := dialer.Dial("tcp", addr)

	if err != nil {
		result.Error = err
		result.RTT = time.Since(start)
		return result
	}

	if p.opts.UseTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         p.opts.Host,
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			result.Error = fmt.Errorf("TLS handshake: %w", err)
			result.RTT = time.Since(start)
			return result
		}
		result.Detail = fmt.Sprintf("TLS %s", tlsVersionString(tlsConn.ConnectionState().Version))
		tlsConn.Close()
	} else {
		conn.Close()
	}

	result.RTT = time.Since(start)
	result.Success = true
	result.Addr = addr
	return result
}

// probeUDP sends a UDP packet and waits for a response or ICMP unreachable.
func (p *Pinger) probeUDP(seq int) ProbeResult {
	result := ProbeResult{
		Seq:      seq,
		Protocol: ProtoUDP,
	}

	addr := fmt.Sprintf("%s:%d", p.opts.Host, p.opts.Port)
	start := time.Now()

	conn, err := net.DialTimeout("udp", addr, p.opts.Timeout)
	if err != nil {
		result.Error = err
		result.RTT = time.Since(start)
		return result
	}
	defer conn.Close()

	// Send a small probe
	probe := []byte{0x00}
	conn.SetWriteDeadline(time.Now().Add(p.opts.Timeout))
	_, err = conn.Write(probe)
	if err != nil {
		result.Error = err
		result.RTT = time.Since(start)
		return result
	}

	// Try to get a response (many UDP services won't respond)
	conn.SetReadDeadline(time.Now().Add(p.opts.Timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)

	result.RTT = time.Since(start)

	if err != nil {
		// Timeout is expected for many UDP services — mark port as "open|filtered"
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.Success = true
			result.Detail = "open|filtered (no response)"
			result.Addr = addr
			return result
		}
		result.Error = err
		return result
	}

	result.Success = true
	result.Detail = fmt.Sprintf("%d bytes response", n)
	result.Addr = addr
	return result
}

// probeHTTP performs an HTTP request probe.
func (p *Pinger) probeHTTP(seq int) ProbeResult {
	result := ProbeResult{
		Seq:      seq,
		Protocol: ProtoHTTP,
	}

	scheme := "http"
	if p.opts.UseTLS || p.opts.Port == 443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, p.opts.Host, p.opts.Port, p.opts.HTTPPath)

	client := &http.Client{
		Timeout: p.opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()

	resp, err := client.Get(url)
	result.RTT = time.Since(start)

	if err != nil {
		result.Error = err
		return result
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	result.Success = true
	result.Detail = fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	result.Addr = url
	return result
}

// probeDNS sends a DNS query and measures response time.
func (p *Pinger) probeDNS(seq int) ProbeResult {
	result := ProbeResult{
		Seq:      seq,
		Protocol: ProtoDNS,
	}

	addr := fmt.Sprintf("%s:%d", p.opts.Host, p.opts.Port)
	start := time.Now()

	conn, err := net.DialTimeout("udp", addr, p.opts.Timeout)
	if err != nil {
		result.Error = err
		result.RTT = time.Since(start)
		return result
	}
	defer conn.Close()

	// Build a simple DNS query for "." (root)
	query := buildDNSProbe()
	conn.SetWriteDeadline(time.Now().Add(p.opts.Timeout))
	_, err = conn.Write(query)
	if err != nil {
		result.Error = fmt.Errorf("write: %w", err)
		result.RTT = time.Since(start)
		return result
	}

	conn.SetReadDeadline(time.Now().Add(p.opts.Timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	result.RTT = time.Since(start)

	if err != nil {
		result.Error = fmt.Errorf("read: %w", err)
		return result
	}

	if n >= 12 {
		flags := uint16(buf[2])<<8 | uint16(buf[3])
		rcode := flags & 0x0F
		anCount := uint16(buf[6])<<8 | uint16(buf[7])
		result.Success = true
		result.Detail = fmt.Sprintf("rcode=%d answers=%d", rcode, anCount)
		result.Addr = addr
	} else {
		result.Error = fmt.Errorf("response too short (%d bytes)", n)
	}

	return result
}

func buildDNSProbe() []byte {
	return []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags: standard query, recursion desired
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		// Query: "." (root) type A class IN
		0x00,       // root label
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// Format returns formatted statistics.
func (s *Statistics) Format(host string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n--- %s %s ping statistics ---\n", host, s.Protocol))
	sb.WriteString(fmt.Sprintf("%d probes sent, %d received, %.1f%% loss\n",
		s.Sent, s.Received, s.LossPercent))

	if s.Received > 0 {
		sb.WriteString(fmt.Sprintf("\nRTT min/avg/max/mdev = %v/%v/%v/%v\n",
			s.MinRTT.Round(time.Microsecond),
			s.AvgRTT.Round(time.Microsecond),
			s.MaxRTT.Round(time.Microsecond),
			s.StdDev.Round(time.Microsecond)))

		if s.Sent > 1 {
			sb.WriteString(fmt.Sprintf("P95: %v  P99: %v  Median: %v\n",
				s.P95.Round(time.Microsecond),
				s.P99.Round(time.Microsecond),
				s.MedianRTT.Round(time.Microsecond)))
		}

		sb.WriteString(fmt.Sprintf("\nQuality: %s\n", s.Quality()))
	}

	return sb.String()
}
