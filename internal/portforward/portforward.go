// Package portforward provides TCP port forwarding functionality.
package portforward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds configuration for the port forwarder.
type Config struct {
	LocalAddr   string        // Local address to listen on (e.g., "127.0.0.1:8080")
	RemoteAddr  string        // Remote address to forward to (e.g., "example.com:80")
	DialTimeout time.Duration // Timeout for connecting to remote
	BufferSize  int           // Buffer size for data transfer (default: 32KB)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		LocalAddr:   "127.0.0.1:8080",
		DialTimeout: 10 * time.Second,
		BufferSize:  32 * 1024,
	}
}

// Stats holds forwarding statistics.
type Stats struct {
	ActiveConns   int64  // Current active connections
	TotalConns    int64  // Total connections handled
	BytesSent     uint64 // Bytes sent to remote
	BytesReceived uint64 // Bytes received from remote
	Errors        int64  // Total errors
}

// Forwarder represents a TCP port forwarder.
type Forwarder struct {
	config   Config
	stats    Stats
	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup

	// Callbacks
	onConnect    func(clientAddr, remoteAddr string)
	onDisconnect func(clientAddr string, duration time.Duration, bytesSent, bytesRecv uint64)
	onError      func(clientAddr string, err error)
}

// New creates a new port forwarder with the given configuration.
func New(cfg Config) (*Forwarder, error) {
	if cfg.LocalAddr == "" {
		return nil, errors.New("local address is required")
	}
	if cfg.RemoteAddr == "" {
		return nil, errors.New("remote address is required")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 32 * 1024
	}

	return &Forwarder{
		config: cfg,
		done:   make(chan struct{}),
	}, nil
}

// OnConnect sets a callback for new connections.
func (f *Forwarder) OnConnect(fn func(clientAddr, remoteAddr string)) {
	f.onConnect = fn
}

// OnDisconnect sets a callback for closed connections.
func (f *Forwarder) OnDisconnect(fn func(clientAddr string, duration time.Duration, bytesSent, bytesRecv uint64)) {
	f.onDisconnect = fn
}

// OnError sets a callback for errors.
func (f *Forwarder) OnError(fn func(clientAddr string, err error)) {
	f.onError = fn
}

// Start starts the port forwarder. It blocks until Stop() is called or an error occurs.
func (f *Forwarder) Start(ctx context.Context) error {
	var err error
	f.listener, err = net.Listen("tcp", f.config.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", f.config.LocalAddr, err)
	}

	// Close listener when context is cancelled
	go func() {
		select {
		case <-ctx.Done():
			f.listener.Close()
		case <-f.done:
		}
	}()

	for {
		conn, err := f.listener.Accept()
		if err != nil {
			select {
			case <-f.done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			default:
				if f.onError != nil {
					f.onError("", fmt.Errorf("accept error: %w", err))
				}
				atomic.AddInt64(&f.stats.Errors, 1)
				continue
			}
		}

		f.wg.Add(1)
		go f.handleConnection(ctx, conn)
	}
}

// Stop stops the port forwarder gracefully.
func (f *Forwarder) Stop() error {
	close(f.done)
	if f.listener != nil {
		f.listener.Close()
	}
	f.wg.Wait()
	return nil
}

// Stats returns current forwarding statistics.
func (f *Forwarder) Stats() Stats {
	return Stats{
		ActiveConns:   atomic.LoadInt64(&f.stats.ActiveConns),
		TotalConns:    atomic.LoadInt64(&f.stats.TotalConns),
		BytesSent:     atomic.LoadUint64(&f.stats.BytesSent),
		BytesReceived: atomic.LoadUint64(&f.stats.BytesReceived),
		Errors:        atomic.LoadInt64(&f.stats.Errors),
	}
}

// LocalAddr returns the actual local address being listened on.
func (f *Forwarder) LocalAddr() string {
	if f.listener != nil {
		return f.listener.Addr().String()
	}
	return f.config.LocalAddr
}

// handleConnection handles a single client connection.
func (f *Forwarder) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer f.wg.Done()
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	startTime := time.Now()

	atomic.AddInt64(&f.stats.TotalConns, 1)
	atomic.AddInt64(&f.stats.ActiveConns, 1)
	defer atomic.AddInt64(&f.stats.ActiveConns, -1)

	// Connect to remote
	dialer := net.Dialer{Timeout: f.config.DialTimeout}
	remoteConn, err := dialer.DialContext(ctx, "tcp", f.config.RemoteAddr)
	if err != nil {
		if f.onError != nil {
			f.onError(clientAddr, fmt.Errorf("failed to connect to remote: %w", err))
		}
		atomic.AddInt64(&f.stats.Errors, 1)
		return
	}
	defer remoteConn.Close()

	if f.onConnect != nil {
		f.onConnect(clientAddr, f.config.RemoteAddr)
	}

	var bytesSent, bytesRecv uint64

	// Bidirectional copy
	errCh := make(chan error, 2)
	go func() {
		n, err := f.copy(remoteConn, clientConn) // client -> remote
		atomic.AddUint64(&f.stats.BytesSent, uint64(n))
		bytesSent = uint64(n)
		errCh <- err
	}()
	go func() {
		n, err := f.copy(clientConn, remoteConn) // remote -> client
		atomic.AddUint64(&f.stats.BytesReceived, uint64(n))
		bytesRecv = uint64(n)
		errCh <- err
	}()

	// Wait for either direction to complete
	select {
	case <-ctx.Done():
	case <-f.done:
	case <-errCh:
	}

	if f.onDisconnect != nil {
		f.onDisconnect(clientAddr, time.Since(startTime), bytesSent, bytesRecv)
	}
}

// copy copies data from src to dst, returning the number of bytes copied.
func (f *Forwarder) copy(dst, src net.Conn) (int64, error) {
	buf := make([]byte, f.config.BufferSize)
	return io.CopyBuffer(dst, src, buf)
}

// FormatBytes formats bytes in human-readable form.
func FormatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// FormatStats formats statistics for display.
func FormatStats(s Stats) string {
	return fmt.Sprintf(`--- Port Forward Statistics ---
Active Connections: %d
Total Connections:  %d
Bytes Sent:         %s
Bytes Received:     %s
Errors:             %d`,
		s.ActiveConns,
		s.TotalConns,
		FormatBytes(s.BytesSent),
		FormatBytes(s.BytesReceived),
		s.Errors)
}
