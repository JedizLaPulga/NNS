// Package wait provides utilities to wait for network services to become available.
package wait

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// Protocol represents the connection protocol.
type Protocol string

const (
	TCP Protocol = "tcp"
	TLS Protocol = "tls"
	UDP Protocol = "udp"
)

// Target represents a wait target.
type Target struct {
	Host     string
	Port     int
	Protocol Protocol
}

// Address returns the host:port address.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
}

// Config holds configuration for the waiter.
type Config struct {
	Timeout  time.Duration // Overall timeout
	Interval time.Duration // Check interval
	Quiet    bool          // Suppress progress output
}

// DefaultConfig returns a default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:  60 * time.Second,
		Interval: 1 * time.Second,
		Quiet:    false,
	}
}

// Result holds the result of a wait operation.
type Result struct {
	Target   Target
	Success  bool
	Duration time.Duration // Time waited
	Attempts int           // Number of attempts made
	Error    error         // Final error if failed
}

// ProgressFunc is called on each attempt.
type ProgressFunc func(attempt int, elapsed time.Duration, err error)

// Waiter provides functionality to wait for services.
type Waiter struct {
	config   Config
	progress ProgressFunc
}

// New creates a new Waiter.
func New(cfg Config) *Waiter {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Second
	}
	return &Waiter{config: cfg}
}

// SetProgressFunc sets a callback for progress updates.
func (w *Waiter) SetProgressFunc(fn ProgressFunc) {
	w.progress = fn
}

// Wait waits for the target to become available.
func (w *Waiter) Wait(ctx context.Context, target Target) Result {
	result := Result{Target: target}
	start := time.Now()
	deadline := start.Add(w.config.Timeout)

	for {
		result.Attempts++
		err := w.tryConnect(ctx, target)

		if err == nil {
			result.Success = true
			result.Duration = time.Since(start)
			return result
		}

		if w.progress != nil {
			w.progress(result.Attempts, time.Since(start), err)
		}

		// Check if we've exceeded the timeout
		if time.Now().After(deadline) {
			result.Error = fmt.Errorf("timeout after %d attempts: %w", result.Attempts, err)
			result.Duration = time.Since(start)
			return result
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			result.Duration = time.Since(start)
			return result
		default:
		}

		// Wait before next attempt
		select {
		case <-time.After(w.config.Interval):
		case <-ctx.Done():
			result.Error = ctx.Err()
			result.Duration = time.Since(start)
			return result
		}
	}
}

// tryConnect attempts a single connection.
func (w *Waiter) tryConnect(ctx context.Context, target Target) error {
	addr := target.Address()
	dialTimeout := w.config.Interval
	if dialTimeout > 5*time.Second {
		dialTimeout = 5 * time.Second
	}

	switch target.Protocol {
	case TLS:
		host, _, _ := net.SplitHostPort(addr)
		dialer := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: dialTimeout},
			Config:    &tls.Config{ServerName: host, InsecureSkipVerify: true},
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		conn.Close()
		return nil

	case UDP:
		dialer := net.Dialer{Timeout: dialTimeout}
		conn, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return err
		}
		// For UDP, we just check if we can "connect"
		conn.Close()
		return nil

	default: // TCP
		dialer := net.Dialer{Timeout: dialTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}
}

// WaitMultiple waits for multiple targets concurrently.
// Returns when all targets are available or timeout is reached.
func (w *Waiter) WaitMultiple(ctx context.Context, targets []Target) []Result {
	results := make([]Result, len(targets))
	done := make(chan int, len(targets))

	ctx, cancel := context.WithTimeout(ctx, w.config.Timeout)
	defer cancel()

	for i, target := range targets {
		go func(idx int, tgt Target) {
			results[idx] = w.Wait(ctx, tgt)
			done <- idx
		}(i, target)
	}

	// Wait for all to complete
	for range targets {
		<-done
	}

	return results
}

// WaitAny waits for any one of the targets to become available.
// Returns the first successful result.
func (w *Waiter) WaitAny(ctx context.Context, targets []Target) Result {
	ctx, cancel := context.WithTimeout(ctx, w.config.Timeout)
	defer cancel()

	resultChan := make(chan Result, len(targets))

	for _, target := range targets {
		go func(tgt Target) {
			result := w.Wait(ctx, tgt)
			resultChan <- result
		}(target)
	}

	// Wait for first success or all to fail
	var lastResult Result
	successCount := 0
	for range targets {
		result := <-resultChan
		if result.Success {
			cancel() // Cancel other waiters
			return result
		}
		lastResult = result
		successCount++
	}

	return lastResult
}

// ParseTarget parses a string like "host:port" into a Target.
func ParseTarget(s string) (Target, error) {
	var t Target
	t.Protocol = TCP

	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return t, fmt.Errorf("invalid format (expected host:port): %w", err)
	}

	t.Host = host
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil || port <= 0 || port > 65535 {
		return t, errors.New("invalid port number")
	}
	t.Port = port

	return t, nil
}

// FormatResult formats a result for display.
func FormatResult(r Result) string {
	if r.Success {
		return fmt.Sprintf("✓ %s:%d is available (waited %.2fs, %d attempts)",
			r.Target.Host, r.Target.Port,
			r.Duration.Seconds(), r.Attempts)
	}
	return fmt.Sprintf("✕ %s:%d is not available after %.2fs (%d attempts): %v",
		r.Target.Host, r.Target.Port,
		r.Duration.Seconds(), r.Attempts, r.Error)
}
