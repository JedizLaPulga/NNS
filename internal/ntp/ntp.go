// Package ntp provides NTP server checking and time offset analysis.
package ntp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ntpEpochOffset = 2208988800 // Seconds between 1900 and 1970
	ntpPort        = 123
)

// Server represents an NTP server.
type Server struct {
	Name    string
	Address string
	Stratum int
}

// PublicServers contains well-known public NTP servers.
var PublicServers = []Server{
	{Name: "pool.ntp.org", Address: "pool.ntp.org:123"},
	{Name: "time.google.com", Address: "time.google.com:123"},
	{Name: "time.cloudflare.com", Address: "time.cloudflare.com:123"},
	{Name: "time.windows.com", Address: "time.windows.com:123"},
	{Name: "time.apple.com", Address: "time.apple.com:123"},
	{Name: "time.nist.gov", Address: "time.nist.gov:123"},
}

// Result contains NTP query result.
type Result struct {
	Server      Server
	Reachable   bool
	ServerTime  time.Time
	LocalTime   time.Time
	Offset      time.Duration
	RTT         time.Duration
	Stratum     int
	Leap        int
	Precision   int
	ReferenceID string
	Error       string
}

// CheckResult contains multi-server check results.
type CheckResult struct {
	Results      []Result
	BestServer   *Result
	AvgOffset    time.Duration
	MaxOffset    time.Duration
	LocalClockOK bool
	Synced       bool
	StartTime    time.Time
	Duration     time.Duration
}

// Config holds NTP checker configuration.
type Config struct {
	Servers []Server
	Timeout time.Duration
	Retries int
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Servers: PublicServers[:4],
		Timeout: 5 * time.Second,
		Retries: 1,
	}
}

// Checker performs NTP checks.
type Checker struct {
	config Config
}

// New creates a new NTP checker.
func New(cfg Config) *Checker {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if len(cfg.Servers) == 0 {
		cfg.Servers = PublicServers[:4]
	}
	return &Checker{config: cfg}
}

// QueryServer queries a single NTP server.
func (c *Checker) QueryServer(ctx context.Context, server Server) Result {
	result := Result{Server: server, LocalTime: time.Now()}

	addr := server.Address
	if !strings.Contains(addr, ":") {
		addr = addr + ":123"
	}

	conn, err := net.DialTimeout("udp", addr, c.config.Timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.config.Timeout)
	}
	conn.SetDeadline(deadline)

	// Build NTP request packet
	request := make([]byte, 48)
	request[0] = 0x1B // LI=0, VN=3, Mode=3 (client)

	t1 := time.Now()
	_, err = conn.Write(request)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	response := make([]byte, 48)
	n, err := conn.Read(response)
	t4 := time.Now()

	if err != nil {
		result.Error = err.Error()
		return result
	}
	if n < 48 {
		result.Error = "incomplete NTP response"
		return result
	}

	result.Reachable = true
	result.RTT = t4.Sub(t1)

	// Parse response
	result.Leap = int(response[0] >> 6)
	result.Stratum = int(response[1])
	result.Precision = int(int8(response[3]))

	// Reference ID
	result.ReferenceID = parseReferenceID(response[12:16], result.Stratum)

	// Extract transmit timestamp (bytes 40-47)
	secs := binary.BigEndian.Uint32(response[40:44])
	frac := binary.BigEndian.Uint32(response[44:48])

	// Convert to Go time
	t3 := ntpToTime(secs, frac)
	result.ServerTime = t3

	// Calculate offset: ((t2-t1) + (t3-t4)) / 2
	// Simplified: we use t3 as server time
	result.Offset = result.ServerTime.Sub(t4.Add(-result.RTT / 2))

	return result
}

// CheckAll checks all configured servers.
func (c *Checker) CheckAll(ctx context.Context) *CheckResult {
	result := &CheckResult{StartTime: time.Now()}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, server := range c.config.Servers {
		wg.Add(1)
		go func(s Server) {
			defer wg.Done()
			r := c.QueryServer(ctx, s)
			mu.Lock()
			result.Results = append(result.Results, r)
			mu.Unlock()
		}(server)
	}

	wg.Wait()
	result.Duration = time.Since(result.StartTime)

	// Sort by RTT
	sort.Slice(result.Results, func(i, j int) bool {
		if !result.Results[i].Reachable {
			return false
		}
		if !result.Results[j].Reachable {
			return true
		}
		return result.Results[i].RTT < result.Results[j].RTT
	})

	// Find best server and calculate stats
	c.analyzeResults(result)

	return result
}

func (c *Checker) analyzeResults(result *CheckResult) {
	var offsets []time.Duration
	var totalOffset time.Duration

	for i := range result.Results {
		r := &result.Results[i]
		if r.Reachable {
			if result.BestServer == nil {
				result.BestServer = r
			}
			offsets = append(offsets, r.Offset)
			totalOffset += r.Offset

			if absOffset(r.Offset) > absOffset(result.MaxOffset) {
				result.MaxOffset = r.Offset
			}
		}
	}

	if len(offsets) > 0 {
		result.AvgOffset = totalOffset / time.Duration(len(offsets))
		result.LocalClockOK = absOffset(result.AvgOffset) < 1*time.Second
		result.Synced = absOffset(result.AvgOffset) < 100*time.Millisecond
	}
}

func absOffset(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func ntpToTime(secs, frac uint32) time.Time {
	nsec := (int64(frac) * 1e9) >> 32
	return time.Unix(int64(secs)-ntpEpochOffset, nsec)
}

func parseReferenceID(data []byte, stratum int) string {
	if stratum <= 1 {
		// ASCII identifier
		return strings.TrimRight(string(data), "\x00")
	}
	// IPv4 address for stratum 2+
	return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
}

// Format returns formatted check results.
func (r *CheckResult) Format() string {
	var sb strings.Builder

	sb.WriteString("NTP Server Check Results\n")
	sb.WriteString(strings.Repeat("─", 70) + "\n\n")

	sb.WriteString(fmt.Sprintf("%-25s %10s %12s %10s %s\n", "Server", "RTT", "Offset", "Stratum", "Status"))
	sb.WriteString(strings.Repeat("─", 70) + "\n")

	for _, res := range r.Results {
		if res.Reachable {
			offsetStr := formatOffset(res.Offset)
			sb.WriteString(fmt.Sprintf("%-25s %10v %12s %10d ✓\n",
				res.Server.Name, res.RTT.Round(time.Millisecond), offsetStr, res.Stratum))
		} else {
			sb.WriteString(fmt.Sprintf("%-25s %10s %12s %10s ✗\n",
				res.Server.Name, "--", "--", "--"))
		}
	}

	sb.WriteString(strings.Repeat("─", 70) + "\n\n")

	// Summary
	if r.BestServer != nil {
		sb.WriteString(fmt.Sprintf("⏱️  Best Server: %s (%v RTT)\n", r.BestServer.Server.Name, r.BestServer.RTT.Round(time.Millisecond)))
	}

	sb.WriteString(fmt.Sprintf("📊 Average Offset: %s\n", formatOffset(r.AvgOffset)))

	if r.LocalClockOK {
		sb.WriteString("✅ Local clock is synchronized (within 1s)\n")
	} else {
		sb.WriteString(fmt.Sprintf("⚠️  Local clock may be off by %s\n", formatOffset(r.AvgOffset)))
	}

	return sb.String()
}

func formatOffset(d time.Duration) string {
	if d < 0 {
		return fmt.Sprintf("-%v", (-d).Round(time.Millisecond))
	}
	return fmt.Sprintf("+%v", d.Round(time.Millisecond))
}
