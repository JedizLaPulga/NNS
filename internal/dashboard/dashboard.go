// Package dashboard provides a TUI dashboard combining network monitoring tools.
package dashboard

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Panel represents a dashboard panel type.
type Panel string

const (
	PanelBandwidth   Panel = "bandwidth"
	PanelLatency     Panel = "latency"
	PanelConnections Panel = "connections"
)

// Config holds dashboard configuration.
type Config struct {
	RefreshInterval time.Duration
	Panels          []Panel
	LatencyTargets  []string
	Simulate        bool
}

// DefaultConfig returns default dashboard configuration.
func DefaultConfig() Config {
	return Config{
		RefreshInterval: 1 * time.Second,
		Panels:          []Panel{PanelBandwidth, PanelLatency, PanelConnections},
		LatencyTargets:  []string{"8.8.8.8", "1.1.1.1"},
		Simulate:        false,
	}
}

// Stats holds current dashboard statistics.
type Stats struct {
	Timestamp   time.Time
	Bandwidth   []BandwidthStats
	Latency     []LatencyStats
	Connections []ConnectionStats
}

// BandwidthStats holds bandwidth statistics.
type BandwidthStats struct {
	Interface string
	RxRate    float64
	TxRate    float64
}

// LatencyStats holds latency statistics.
type LatencyStats struct {
	Target  string
	Latency time.Duration
	Jitter  time.Duration
	Loss    float64
}

// ConnectionStats holds connection statistics.
type ConnectionStats struct {
	Protocol   string
	LocalAddr  string
	RemoteAddr string
	State      string
}

// Dashboard provides the TUI dashboard functionality.
type Dashboard struct {
	config    Config
	mu        sync.RWMutex
	stats     Stats
	running   bool
	stopChan  chan struct{}
	iteration int
	prevStats map[string]prevBwStats
}

type prevBwStats struct {
	rx, tx    uint64
	timestamp time.Time
}

// New creates a new Dashboard.
func New(cfg Config) *Dashboard {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = time.Second
	}
	return &Dashboard{
		config:    cfg,
		stopChan:  make(chan struct{}),
		prevStats: make(map[string]prevBwStats),
	}
}

// Start starts the dashboard update loop.
func (d *Dashboard) Start(ctx context.Context) {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.mu.Unlock()
	go d.updateLoop(ctx)
}

// Stop stops the dashboard.
func (d *Dashboard) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running {
		d.running = false
		close(d.stopChan)
	}
}

// GetStats returns current statistics.
func (d *Dashboard) GetStats() Stats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.stats
}

func (d *Dashboard) updateLoop(ctx context.Context) {
	ticker := time.NewTicker(d.config.RefreshInterval)
	defer ticker.Stop()
	d.update()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopChan:
			return
		case <-ticker.C:
			d.update()
		}
	}
}

func (d *Dashboard) update() {
	d.iteration++
	stats := Stats{Timestamp: time.Now()}
	stats.Bandwidth = d.gatherBandwidth()
	stats.Latency = d.gatherLatency()
	stats.Connections = d.gatherConnections()
	d.mu.Lock()
	d.stats = stats
	d.mu.Unlock()
}

func (d *Dashboard) gatherBandwidth() []BandwidthStats {
	now := time.Now()
	eth0Rx := uint64(d.iteration) * 200000
	eth0Tx := uint64(d.iteration) * 100000
	var stats []BandwidthStats
	if prev, ok := d.prevStats["eth0"]; ok {
		elapsed := now.Sub(prev.timestamp).Seconds()
		if elapsed > 0 {
			stats = append(stats, BandwidthStats{
				Interface: "eth0",
				RxRate:    float64(eth0Rx-prev.rx) / elapsed,
				TxRate:    float64(eth0Tx-prev.tx) / elapsed,
			})
		}
	}
	d.prevStats["eth0"] = prevBwStats{rx: eth0Rx, tx: eth0Tx, timestamp: now}
	return stats
}

func (d *Dashboard) gatherLatency() []LatencyStats {
	var stats []LatencyStats
	for _, target := range d.config.LatencyTargets {
		if d.config.Simulate {
			stats = append(stats, LatencyStats{Target: target, Latency: 20 * time.Millisecond})
		} else {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", target+":80", time.Second)
			if err == nil {
				conn.Close()
				stats = append(stats, LatencyStats{Target: target, Latency: time.Since(start)})
			} else {
				stats = append(stats, LatencyStats{Target: target, Loss: 100})
			}
		}
	}
	return stats
}

func (d *Dashboard) gatherConnections() []ConnectionStats {
	if d.config.Simulate {
		return []ConnectionStats{
			{Protocol: "tcp", LocalAddr: "127.0.0.1:8080", RemoteAddr: "0.0.0.0:*", State: "LISTEN"},
		}
	}
	return nil
}

// Render renders the dashboard to a string.
func (d *Dashboard) Render(width int) string {
	d.mu.RLock()
	stats := d.stats
	d.mu.RUnlock()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("╔%s╗\n", strings.Repeat("═", width-2)))
	sb.WriteString(fmt.Sprintf("║ NNS Dashboard - %s%s║\n", stats.Timestamp.Format("15:04:05"), strings.Repeat(" ", width-28)))
	sb.WriteString(fmt.Sprintf("╠%s╣\n", strings.Repeat("═", width-2)))
	for _, bw := range stats.Bandwidth {
		line := fmt.Sprintf(" %-8s ↓%.2f KB/s ↑%.2f KB/s", bw.Interface, bw.RxRate/1024, bw.TxRate/1024)
		sb.WriteString(fmt.Sprintf("║%-*s║\n", width-2, line))
	}
	for _, lat := range stats.Latency {
		line := fmt.Sprintf(" %-15s %.2fms", lat.Target, float64(lat.Latency.Microseconds())/1000)
		sb.WriteString(fmt.Sprintf("║%-*s║\n", width-2, line))
	}
	sb.WriteString(fmt.Sprintf("╚%s╝\n", strings.Repeat("═", width-2)))
	return sb.String()
}

// ClearScreen returns ANSI escape sequence to clear screen.
func ClearScreen() string { return "\033[2J\033[H" }
