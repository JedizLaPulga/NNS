// Package bandwidth provides network bandwidth testing functionality.
package bandwidth

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Result holds bandwidth test results.
type Result struct {
	Direction     string // "download", "upload", or "both"
	Duration      time.Duration
	BytesSent     int64
	BytesReceived int64
	UploadSpeed   float64 // Mbps
	DownloadSpeed float64 // Mbps
	Latency       time.Duration
	Jitter        time.Duration
	PacketLoss    float64
}

// Config configures the bandwidth test.
type Config struct {
	Target     string
	Port       int
	Duration   time.Duration
	BufferSize int
	Parallel   int
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Port:       5201,
		Duration:   10 * time.Second,
		BufferSize: 128 * 1024, // 128KB
		Parallel:   1,
	}
}

// Server runs a bandwidth test server.
type Server struct {
	Port       int
	BufferSize int
	listener   net.Listener
	running    bool
	mu         sync.Mutex
}

// NewServer creates a new bandwidth test server.
func NewServer(port int) *Server {
	return &Server{
		Port:       port,
		BufferSize: 128 * 1024,
	}
}

// Start starts the bandwidth server.
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	for {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()

		if !running {
			break
		}

		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go s.handleConnection(conn)
	}

	return nil
}

// Stop stops the bandwidth server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read command byte
	cmd := make([]byte, 1)
	conn.Read(cmd)

	switch cmd[0] {
	case 'D': // Download test - server sends data
		data := make([]byte, s.BufferSize)
		rand.Read(data)
		for {
			_, err := conn.Write(data)
			if err != nil {
				break
			}
		}
	case 'U': // Upload test - server receives data
		buf := make([]byte, s.BufferSize)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				break
			}
		}
	case 'P': // Ping - echo back
		buf := make([]byte, 64)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			conn.Write(buf[:n])
		}
	}
}

// Client performs bandwidth tests.
type Client struct {
	Config Config
}

// NewClient creates a new bandwidth test client.
func NewClient(cfg Config) *Client {
	return &Client{Config: cfg}
}

// TestDownload performs a download speed test.
func (c *Client) TestDownload(ctx context.Context) (*Result, error) {
	result := &Result{Direction: "download"}

	// Connect to server
	addr := fmt.Sprintf("%s:%d", c.Config.Target, c.Config.Port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Send download command
	conn.Write([]byte("D"))

	// Measure download
	buf := make([]byte, c.Config.BufferSize)
	start := time.Now()
	deadline := start.Add(c.Config.Duration)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			break
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		result.BytesReceived += int64(n)
	}

	result.Duration = time.Since(start)
	result.DownloadSpeed = float64(result.BytesReceived*8) / result.Duration.Seconds() / 1_000_000

	return result, nil
}

// TestUpload performs an upload speed test.
func (c *Client) TestUpload(ctx context.Context) (*Result, error) {
	result := &Result{Direction: "upload"}

	// Connect to server
	addr := fmt.Sprintf("%s:%d", c.Config.Target, c.Config.Port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Send upload command
	conn.Write([]byte("U"))

	// Generate random data
	data := make([]byte, c.Config.BufferSize)
	rand.Read(data)

	// Measure upload
	start := time.Now()
	deadline := start.Add(c.Config.Duration)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			break
		default:
		}

		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Write(data)
		if err != nil {
			continue
		}
		result.BytesSent += int64(n)
	}

	result.Duration = time.Since(start)
	result.UploadSpeed = float64(result.BytesSent*8) / result.Duration.Seconds() / 1_000_000

	return result, nil
}

// TestLatency measures latency and jitter.
func (c *Client) TestLatency(ctx context.Context, samples int) (*Result, error) {
	result := &Result{Direction: "latency"}

	// Connect to server
	addr := fmt.Sprintf("%s:%d", c.Config.Target, c.Config.Port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Send ping command
	conn.Write([]byte("P"))

	// Measure latency
	latencies := make([]time.Duration, 0, samples)
	data := make([]byte, 64)
	buf := make([]byte, 64)
	rand.Read(data)

	for i := 0; i < samples; i++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		start := time.Now()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		_, err := conn.Write(data)
		if err != nil {
			continue
		}

		_, err = conn.Read(buf)
		if err != nil {
			continue
		}

		latencies = append(latencies, time.Since(start))
		time.Sleep(100 * time.Millisecond)
	}

	if len(latencies) == 0 {
		return nil, fmt.Errorf("no successful latency samples")
	}

	// Calculate average latency
	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	result.Latency = total / time.Duration(len(latencies))

	// Calculate jitter (average deviation)
	if len(latencies) > 1 {
		var jitterSum time.Duration
		for i := 1; i < len(latencies); i++ {
			diff := latencies[i] - latencies[i-1]
			if diff < 0 {
				diff = -diff
			}
			jitterSum += diff
		}
		result.Jitter = jitterSum / time.Duration(len(latencies)-1)
	}

	result.PacketLoss = float64(samples-len(latencies)) / float64(samples) * 100

	return result, nil
}

// FormatSpeed formats speed in human-readable format.
func FormatSpeed(mbps float64) string {
	if mbps >= 1000 {
		return fmt.Sprintf("%.2f Gbps", mbps/1000)
	}
	return fmt.Sprintf("%.2f Mbps", mbps)
}

// FormatBytes formats bytes in human-readable format.
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
