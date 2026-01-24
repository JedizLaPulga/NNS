// Package listen provides TCP/UDP listener utilities for connectivity testing.
package listen

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Protocol represents the network protocol.
type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

// Connection represents an active connection.
type Connection struct {
	ID         uint64
	RemoteAddr string
	LocalAddr  string
	Protocol   Protocol
	StartTime  time.Time
	BytesRecv  int64
	BytesSent  int64
}

// Event represents a listener event.
type Event struct {
	Type       string // "connect", "disconnect", "data", "error"
	Connection *Connection
	Data       []byte
	Error      error
	Time       time.Time
}

// Config holds listener configuration.
type Config struct {
	Port       int
	Protocol   Protocol
	Host       string // Bind address, default 0.0.0.0
	BufferSize int    // Read buffer size
	Echo       bool   // Echo received data back
	MaxConns   int    // Max concurrent connections (0 = unlimited)
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Port:       8080,
		Protocol:   TCP,
		Host:       "0.0.0.0",
		BufferSize: 4096,
		Echo:       false,
		MaxConns:   0,
	}
}

// Stats holds listener statistics.
type Stats struct {
	TotalConnections   uint64
	ActiveConnections  int64
	TotalBytesReceived int64
	TotalBytesSent     int64
	StartTime          time.Time
}

// Listener provides TCP/UDP listening capabilities.
type Listener struct {
	config      Config
	tcpListener net.Listener
	udpConn     *net.UDPConn
	connections sync.Map
	connCounter uint64
	stats       Stats
	running     atomic.Bool
	mu          sync.RWMutex
}

// New creates a new Listener with the given configuration.
func New(cfg Config) *Listener {
	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.Protocol == "" {
		cfg.Protocol = TCP
	}

	return &Listener{
		config: cfg,
		stats:  Stats{StartTime: time.Now()},
	}
}

// Address returns the listen address.
func (l *Listener) Address() string {
	return fmt.Sprintf("%s:%d", l.config.Host, l.config.Port)
}

// Start starts the listener and calls the callback for each event.
func (l *Listener) Start(ctx context.Context, callback func(Event)) error {
	l.stats.StartTime = time.Now()
	l.running.Store(true)

	switch l.config.Protocol {
	case TCP:
		return l.startTCP(ctx, callback)
	case UDP:
		return l.startUDP(ctx, callback)
	default:
		return fmt.Errorf("unsupported protocol: %s", l.config.Protocol)
	}
}

// startTCP starts a TCP listener.
func (l *Listener) startTCP(ctx context.Context, callback func(Event)) error {
	addr := l.Address()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	l.tcpListener = listener

	defer listener.Close()

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		l.running.Store(false)
		listener.Close()
	}()

	for l.running.Load() {
		conn, err := listener.Accept()
		if err != nil {
			if !l.running.Load() {
				return nil // Normal shutdown
			}
			callback(Event{
				Type:  "error",
				Error: err,
				Time:  time.Now(),
			})
			continue
		}

		// Check max connections
		if l.config.MaxConns > 0 && atomic.LoadInt64(&l.stats.ActiveConnections) >= int64(l.config.MaxConns) {
			conn.Close()
			continue
		}

		go l.handleTCPConnection(ctx, conn, callback)
	}

	return nil
}

// handleTCPConnection handles a single TCP connection.
func (l *Listener) handleTCPConnection(ctx context.Context, conn net.Conn, callback func(Event)) {
	defer conn.Close()

	connID := atomic.AddUint64(&l.connCounter, 1)
	atomic.AddUint64(&l.stats.TotalConnections, 1)
	atomic.AddInt64(&l.stats.ActiveConnections, 1)
	defer atomic.AddInt64(&l.stats.ActiveConnections, -1)

	c := &Connection{
		ID:         connID,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Protocol:   TCP,
		StartTime:  time.Now(),
	}

	l.connections.Store(connID, c)
	defer l.connections.Delete(connID)

	callback(Event{
		Type:       "connect",
		Connection: c,
		Time:       time.Now(),
	})

	buf := make([]byte, l.config.BufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF || !l.running.Load() {
				callback(Event{
					Type:       "disconnect",
					Connection: c,
					Time:       time.Now(),
				})
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			callback(Event{
				Type:       "disconnect",
				Connection: c,
				Error:      err,
				Time:       time.Now(),
			})
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			c.BytesRecv += int64(n)
			atomic.AddInt64(&l.stats.TotalBytesReceived, int64(n))

			callback(Event{
				Type:       "data",
				Connection: c,
				Data:       data,
				Time:       time.Now(),
			})

			// Echo mode
			if l.config.Echo {
				written, _ := conn.Write(data)
				c.BytesSent += int64(written)
				atomic.AddInt64(&l.stats.TotalBytesSent, int64(written))
			}
		}
	}
}

// startUDP starts a UDP listener.
func (l *Listener) startUDP(ctx context.Context, callback func(Event)) error {
	addr, err := net.ResolveUDPAddr("udp", l.Address())
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", l.Address(), err)
	}
	l.udpConn = conn
	defer conn.Close()

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		l.running.Store(false)
		conn.Close()
	}()

	buf := make([]byte, l.config.BufferSize)
	for l.running.Load() {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if !l.running.Load() {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			callback(Event{
				Type:  "error",
				Error: err,
				Time:  time.Now(),
			})
			continue
		}

		if n > 0 {
			connID := atomic.AddUint64(&l.connCounter, 1)
			atomic.AddUint64(&l.stats.TotalConnections, 1)

			c := &Connection{
				ID:         connID,
				RemoteAddr: remoteAddr.String(),
				LocalAddr:  conn.LocalAddr().String(),
				Protocol:   UDP,
				StartTime:  time.Now(),
				BytesRecv:  int64(n),
			}

			data := make([]byte, n)
			copy(data, buf[:n])
			atomic.AddInt64(&l.stats.TotalBytesReceived, int64(n))

			callback(Event{
				Type:       "data",
				Connection: c,
				Data:       data,
				Time:       time.Now(),
			})

			// Echo mode
			if l.config.Echo {
				written, _ := conn.WriteToUDP(data, remoteAddr)
				atomic.AddInt64(&l.stats.TotalBytesSent, int64(written))
			}
		}
	}

	return nil
}

// Stop stops the listener.
func (l *Listener) Stop() error {
	l.running.Store(false)

	if l.tcpListener != nil {
		l.tcpListener.Close()
	}
	if l.udpConn != nil {
		l.udpConn.Close()
	}

	return nil
}

// GetStats returns current statistics.
func (l *Listener) GetStats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return Stats{
		TotalConnections:   atomic.LoadUint64(&l.stats.TotalConnections),
		ActiveConnections:  atomic.LoadInt64(&l.stats.ActiveConnections),
		TotalBytesReceived: atomic.LoadInt64(&l.stats.TotalBytesReceived),
		TotalBytesSent:     atomic.LoadInt64(&l.stats.TotalBytesSent),
		StartTime:          l.stats.StartTime,
	}
}

// GetActiveConnections returns a list of active connections.
func (l *Listener) GetActiveConnections() []*Connection {
	var conns []*Connection
	l.connections.Range(func(key, value interface{}) bool {
		if c, ok := value.(*Connection); ok {
			conns = append(conns, c)
		}
		return true
	})
	return conns
}

// IsRunning returns whether the listener is running.
func (l *Listener) IsRunning() bool {
	return l.running.Load()
}

// FormatEvent formats an event for display.
func FormatEvent(e Event) string {
	timestamp := e.Time.Format("15:04:05")

	switch e.Type {
	case "connect":
		return fmt.Sprintf("[%s] ✓ Connected: %s", timestamp, e.Connection.RemoteAddr)
	case "disconnect":
		duration := time.Since(e.Connection.StartTime)
		return fmt.Sprintf("[%s] ✕ Disconnected: %s (duration: %v, recv: %d, sent: %d)",
			timestamp, e.Connection.RemoteAddr, duration.Round(time.Millisecond),
			e.Connection.BytesRecv, e.Connection.BytesSent)
	case "data":
		preview := string(e.Data)
		if len(preview) > 50 {
			preview = preview[:50] + "..."
		}
		// Replace newlines for display
		preview = fmt.Sprintf("%q", preview)
		return fmt.Sprintf("[%s] ← %s: %d bytes %s",
			timestamp, e.Connection.RemoteAddr, len(e.Data), preview)
	case "error":
		return fmt.Sprintf("[%s] ⚠ Error: %v", timestamp, e.Error)
	default:
		return fmt.Sprintf("[%s] %s", timestamp, e.Type)
	}
}

// FormatStats formats statistics for display.
func FormatStats(s Stats) string {
	uptime := time.Since(s.StartTime)
	return fmt.Sprintf("Uptime: %v | Connections: %d total, %d active | Traffic: %d recv, %d sent",
		uptime.Round(time.Second), s.TotalConnections, s.ActiveConnections,
		s.TotalBytesReceived, s.TotalBytesSent)
}
