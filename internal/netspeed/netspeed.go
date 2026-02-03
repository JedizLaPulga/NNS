// Package netspeed provides internal network speed testing (iperf-like).
package netspeed

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultPort     = 5201
	DefaultDuration = 10 * time.Second
	BufferSize      = 128 * 1024 // 128KB
)

// Role represents server or client role.
type Role string

const (
	RoleServer Role = "server"
	RoleClient Role = "client"
)

// Result contains speed test results.
type Result struct {
	Role          Role
	BytesSent     int64
	BytesReceived int64
	Duration      time.Duration
	SendSpeed     float64 // Mbps
	ReceiveSpeed  float64 // Mbps
	Connections   int
	RemoteAddr    string
	LocalAddr     string
}

// ServerStats contains server statistics.
type ServerStats struct {
	TotalConnections int64
	TotalBytes       int64
	CurrentConns     int64
	StartTime        time.Time
}

// Config holds speed test configuration.
type Config struct {
	Port          int
	Duration      time.Duration
	Connections   int
	BufferSize    int
	Bidirectional bool
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Port:        DefaultPort,
		Duration:    DefaultDuration,
		Connections: 1,
		BufferSize:  BufferSize,
	}
}

// Server implements the speed test server.
type Server struct {
	config   Config
	listener net.Listener
	stats    ServerStats
	mu       sync.RWMutex
	done     chan struct{}
}

// NewServer creates a new speed test server.
func NewServer(cfg Config) *Server {
	if cfg.Port <= 0 {
		cfg.Port = DefaultPort
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = BufferSize
	}
	return &Server{
		config: cfg,
		done:   make(chan struct{}),
	}
}

// Start starts the server.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener
	s.stats.StartTime = time.Now()

	go s.acceptLoop(ctx)
	return nil
}

// Stop stops the server.
func (s *Server) Stop() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
}

// GetStats returns current server statistics.
func (s *Server) GetStats() ServerStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// Address returns the server's listening address.
func (s *Server) Address() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		atomic.AddInt64(&s.stats.TotalConnections, 1)
		atomic.AddInt64(&s.stats.CurrentConns, 1)

		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	defer atomic.AddInt64(&s.stats.CurrentConns, -1)

	buf := make([]byte, s.config.BufferSize)
	start := time.Now()
	var totalBytes int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if test duration exceeded
				if time.Since(start) > s.config.Duration*2 {
					break
				}
				continue
			}
			break
		}

		totalBytes += int64(n)
		atomic.AddInt64(&s.stats.TotalBytes, int64(n))

		// Echo back for bidirectional test
		if s.config.Bidirectional {
			conn.Write(buf[:n])
		}
	}
}

// Client implements the speed test client.
type Client struct {
	config Config
}

// NewClient creates a new speed test client.
func NewClient(cfg Config) *Client {
	if cfg.Duration <= 0 {
		cfg.Duration = DefaultDuration
	}
	if cfg.Connections <= 0 {
		cfg.Connections = 1
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = BufferSize
	}
	return &Client{config: cfg}
}

// Test runs a speed test to the specified server.
func (c *Client) Test(ctx context.Context, host string) (*Result, error) {
	addr := host
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", host, c.config.Port)
	}

	result := &Result{
		Role:        RoleClient,
		Connections: c.config.Connections,
		RemoteAddr:  addr,
	}

	var wg sync.WaitGroup
	var totalSent, totalReceived int64
	var mu sync.Mutex
	var localAddr string

	start := time.Now()

	for i := 0; i < c.config.Connections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			mu.Lock()
			if localAddr == "" {
				localAddr = conn.LocalAddr().String()
			}
			mu.Unlock()

			sent, recv := c.runTest(ctx, conn)
			atomic.AddInt64(&totalSent, sent)
			atomic.AddInt64(&totalReceived, recv)
		}()
	}

	wg.Wait()
	result.Duration = time.Since(start)
	result.BytesSent = totalSent
	result.BytesReceived = totalReceived
	result.LocalAddr = localAddr

	// Calculate speeds in Mbps
	seconds := result.Duration.Seconds()
	if seconds > 0 {
		result.SendSpeed = float64(result.BytesSent*8) / seconds / 1_000_000
		result.ReceiveSpeed = float64(result.BytesReceived*8) / seconds / 1_000_000
	}

	return result, nil
}

func (c *Client) runTest(ctx context.Context, conn net.Conn) (sent, received int64) {
	// Generate random data
	buf := make([]byte, c.config.BufferSize)
	rand.Read(buf)

	deadline := time.Now().Add(c.config.Duration)
	conn.SetDeadline(deadline)

	// Start receiver for bidirectional
	var recvWg sync.WaitGroup
	if c.config.Bidirectional {
		recvWg.Add(1)
		go func() {
			defer recvWg.Done()
			recvBuf := make([]byte, c.config.BufferSize)
			for {
				n, err := conn.Read(recvBuf)
				if err != nil {
					return
				}
				atomic.AddInt64(&received, int64(n))
			}
		}()
	}

	// Send data
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := conn.Write(buf)
		if err != nil {
			break
		}
		sent += int64(n)
	}

	if c.config.Bidirectional {
		recvWg.Wait()
	}

	return
}

// QuickTest performs a quick speed test with default settings.
func QuickTest(ctx context.Context, host string) (*Result, error) {
	client := NewClient(Config{
		Duration:    5 * time.Second,
		Connections: 1,
	})
	return client.Test(ctx, host)
}

// Format returns formatted result.
func (r *Result) Format() string {
	var sb strings.Builder

	sb.WriteString("Network Speed Test Results\n")
	sb.WriteString(strings.Repeat("─", 50) + "\n\n")

	if r.LocalAddr != "" {
		sb.WriteString(fmt.Sprintf("Local:  %s\n", r.LocalAddr))
	}
	sb.WriteString(fmt.Sprintf("Remote: %s\n", r.RemoteAddr))
	sb.WriteString(fmt.Sprintf("Duration: %v\n\n", r.Duration.Round(time.Millisecond)))

	sb.WriteString(fmt.Sprintf("📤 Upload:   %.2f Mbps\n", r.SendSpeed))
	if r.ReceiveSpeed > 0 {
		sb.WriteString(fmt.Sprintf("📥 Download: %.2f Mbps\n", r.ReceiveSpeed))
	}

	sb.WriteString(fmt.Sprintf("\nData Sent: %s\n", formatBytes(r.BytesSent)))
	if r.BytesReceived > 0 {
		sb.WriteString(fmt.Sprintf("Data Received: %s\n", formatBytes(r.BytesReceived)))
	}

	sb.WriteString(fmt.Sprintf("Connections: %d\n", r.Connections))

	return sb.String()
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// BandwidthMonitor monitors bandwidth in real-time.
type BandwidthMonitor struct {
	bytesSent     int64
	bytesReceived int64
	startTime     time.Time
}

// NewBandwidthMonitor creates a new bandwidth monitor.
func NewBandwidthMonitor() *BandwidthMonitor {
	return &BandwidthMonitor{startTime: time.Now()}
}

// WrapReader wraps an io.Reader to monitor bytes read.
func (m *BandwidthMonitor) WrapReader(r io.Reader) io.Reader {
	return &monitoredReader{reader: r, monitor: m}
}

// WrapWriter wraps an io.Writer to monitor bytes written.
func (m *BandwidthMonitor) WrapWriter(w io.Writer) io.Writer {
	return &monitoredWriter{writer: w, monitor: m}
}

// GetStats returns current bandwidth statistics.
func (m *BandwidthMonitor) GetStats() (sent, received int64, elapsed time.Duration) {
	return atomic.LoadInt64(&m.bytesSent),
		atomic.LoadInt64(&m.bytesReceived),
		time.Since(m.startTime)
}

type monitoredReader struct {
	reader  io.Reader
	monitor *BandwidthMonitor
}

func (r *monitoredReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	atomic.AddInt64(&r.monitor.bytesReceived, int64(n))
	return n, err
}

type monitoredWriter struct {
	writer  io.Writer
	monitor *BandwidthMonitor
}

func (w *monitoredWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	atomic.AddInt64(&w.monitor.bytesSent, int64(n))
	return n, err
}
