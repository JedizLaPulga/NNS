// Package portknock implements TCP port knock sequence sending.
package portknock

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// KnockResult holds the result of a single port knock.
type KnockResult struct {
	Port     int
	Seq      int
	Success  bool
	Error    error
	Duration time.Duration
	State    string // "sent", "open", "closed", "filtered"
}

// Options configures a port knock sequence.
type Options struct {
	Host     string
	Ports    []int
	Delay    time.Duration // Delay between knocks
	Timeout  time.Duration // Timeout per knock attempt
	Protocol string        // "tcp" or "udp"
	Verify   int           // Port to verify after knocking (0 = none)
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Delay:    500 * time.Millisecond,
		Timeout:  2 * time.Second,
		Protocol: "tcp",
	}
}

// SequenceResult holds the overall knock sequence result.
type SequenceResult struct {
	Host        string
	Ports       []int
	Results     []KnockResult
	VerifyPort  int
	VerifyState string
	Duration    time.Duration
}

// Knock sends a port knock sequence to the target host.
func Knock(ctx context.Context, opts Options) (*SequenceResult, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if len(opts.Ports) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	if opts.Delay <= 0 {
		opts.Delay = 500 * time.Millisecond
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Protocol == "" {
		opts.Protocol = "tcp"
	}

	start := time.Now()
	result := &SequenceResult{
		Host:    opts.Host,
		Ports:   opts.Ports,
		Results: make([]KnockResult, 0, len(opts.Ports)),
	}

	for i, port := range opts.Ports {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		kr := knockPort(opts.Host, port, i+1, opts.Protocol, opts.Timeout)
		result.Results = append(result.Results, kr)

		// Delay between knocks (but not after the last one)
		if i < len(opts.Ports)-1 {
			select {
			case <-ctx.Done():
				result.Duration = time.Since(start)
				return result, ctx.Err()
			case <-time.After(opts.Delay):
			}
		}
	}

	// Verify port if requested
	if opts.Verify > 0 {
		// Small delay before verification
		select {
		case <-ctx.Done():
		case <-time.After(opts.Delay):
		}

		result.VerifyPort = opts.Verify
		result.VerifyState = probePort(opts.Host, opts.Verify, opts.Protocol, opts.Timeout)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// knockPort attempts to connect+close to a single port as part of the knock.
func knockPort(host string, port, seq int, proto string, timeout time.Duration) KnockResult {
	kr := KnockResult{
		Port: port,
		Seq:  seq,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	switch proto {
	case "tcp":
		conn, err := net.DialTimeout("tcp", addr, timeout)
		kr.Duration = time.Since(start)
		if err != nil {
			if isTimeout(err) {
				kr.State = "filtered"
			} else if isConnectionRefused(err) {
				kr.State = "closed"
			} else {
				kr.State = "filtered"
				kr.Error = err
			}
			kr.Success = true // knock "sent" even if port is closed
			return kr
		}
		conn.Close()
		kr.State = "open"
		kr.Success = true

	case "udp":
		conn, err := net.DialTimeout("udp", addr, timeout)
		kr.Duration = time.Since(start)
		if err != nil {
			kr.State = "filtered"
			kr.Error = err
			return kr
		}
		// Send a small packet
		conn.Write([]byte{0x00})
		conn.Close()
		kr.State = "sent"
		kr.Success = true
	}

	return kr
}

// probePort checks if a port is open after the knock sequence.
func probePort(host string, port int, proto string, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout(proto, addr, timeout)
	if err != nil {
		if isTimeout(err) {
			return "filtered"
		}
		if isConnectionRefused(err) {
			return "closed"
		}
		return "filtered"
	}
	conn.Close()
	return "open"
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func isConnectionRefused(err error) bool {
	return strings.Contains(err.Error(), "refused") ||
		strings.Contains(err.Error(), "connection refused")
}

// FormatResult returns a human-readable summary of the knock result.
func FormatResult(r *SequenceResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("PORT KNOCK %s\n", r.Host))
	sb.WriteString(fmt.Sprintf("Sequence: %v\n", formatPorts(r.Ports)))
	sb.WriteString(fmt.Sprintf("Total time: %v\n\n", r.Duration.Round(time.Millisecond)))

	sb.WriteString("  SEQ  PORT     STATE       TIME\n")
	sb.WriteString("  ───  ─────    ──────      ─────\n")

	for _, kr := range r.Results {
		icon := "✓"
		if !kr.Success {
			icon = "✗"
		}
		sb.WriteString(fmt.Sprintf("  %s %d  %-5d    %-10s  %v\n",
			icon, kr.Seq, kr.Port, kr.State, kr.Duration.Round(time.Microsecond)))
	}

	if r.VerifyPort > 0 {
		sb.WriteString(fmt.Sprintf("\nVerification port %d: %s\n", r.VerifyPort, verifyIcon(r.VerifyState)))
	}

	return sb.String()
}

func formatPorts(ports []int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(strs, " → ")
}

func verifyIcon(state string) string {
	switch state {
	case "open":
		return "🟢 OPEN (knock sequence accepted)"
	case "closed":
		return "🔴 CLOSED (knock may have failed)"
	case "filtered":
		return "🟡 FILTERED (firewall blocking)"
	default:
		return state
	}
}
