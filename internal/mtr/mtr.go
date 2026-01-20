// Package mtr provides My TraceRoute functionality - combining ping and traceroute
// for continuous network path monitoring.
package mtr

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// HopStats holds statistics for a single hop.
type HopStats struct {
	TTL         int             `json:"ttl"`
	IP          string          `json:"ip"`
	Hostname    string          `json:"hostname"`
	Sent        int             `json:"sent"`
	Received    int             `json:"received"`
	Lost        int             `json:"lost"`
	LossPercent float64         `json:"loss_percent"`
	LastRTT     time.Duration   `json:"last_rtt"`
	AvgRTT      time.Duration   `json:"avg_rtt"`
	MinRTT      time.Duration   `json:"min_rtt"`
	MaxRTT      time.Duration   `json:"max_rtt"`
	StdDev      time.Duration   `json:"std_dev"`
	AllRTTs     []time.Duration `json:"-"`
	mu          sync.Mutex
}

// Result holds the complete MTR result.
type Result struct {
	Target      string        `json:"target"`
	ResolvedIP  string        `json:"resolved_ip"`
	Hops        []*HopStats   `json:"hops"`
	TotalCycles int           `json:"total_cycles"`
	StartTime   time.Time     `json:"start_time"`
	Duration    time.Duration `json:"duration"`
}

// Config configures the MTR run.
type Config struct {
	Target      string
	MaxHops     int
	Timeout     time.Duration
	Interval    time.Duration
	Count       int // 0 = infinite until context cancelled
	ResolveHost bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxHops:     30,
		Timeout:     2 * time.Second,
		Interval:    1 * time.Second,
		Count:       10,
		ResolveHost: true,
	}
}

// MTR represents an MTR instance.
type MTR struct {
	cfg    Config
	pid    int
	result *Result
	mu     sync.RWMutex
}

// New creates a new MTR instance.
func New(cfg Config) *MTR {
	if cfg.MaxHops <= 0 {
		cfg.MaxHops = 30
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Second
	}

	m := &MTR{
		cfg: cfg,
		pid: os.Getpid() & 0xffff,
		result: &Result{
			Target:    cfg.Target,
			Hops:      make([]*HopStats, cfg.MaxHops),
			StartTime: time.Now(),
		},
	}

	// Initialize hops
	for i := 0; i < cfg.MaxHops; i++ {
		m.result.Hops[i] = &HopStats{
			TTL:     i + 1,
			AllRTTs: make([]time.Duration, 0),
			MinRTT:  time.Hour,
		}
	}

	return m
}

// Run executes the MTR and calls callback after each cycle.
func (m *MTR) Run(ctx context.Context, callback func(*Result)) error {
	// Resolve target
	dst, err := net.ResolveIPAddr("ip4", m.cfg.Target)
	if err != nil {
		return fmt.Errorf("resolve failed: %w", err)
	}
	m.result.ResolvedIP = dst.String()

	// Initialize hops
	for i := 0; i < m.cfg.MaxHops; i++ {
		m.result.Hops[i] = &HopStats{
			TTL:     i + 1,
			AllRTTs: make([]time.Duration, 0),
			MinRTT:  time.Hour, // Will be updated
		}
	}

	// Open ICMP connection
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("failed to open ICMP (try running as administrator): %w", err)
	}
	defer conn.Close()

	pconn := conn.IPv4PacketConn()

	cycle := 0
	for {
		select {
		case <-ctx.Done():
			m.result.Duration = time.Since(m.result.StartTime)
			m.result.TotalCycles = cycle
			return nil
		default:
		}

		if m.cfg.Count > 0 && cycle >= m.cfg.Count {
			m.result.Duration = time.Since(m.result.StartTime)
			m.result.TotalCycles = cycle
			return nil
		}

		// Run one cycle - probe all TTLs
		m.runCycle(ctx, conn, pconn, dst, cycle)
		cycle++

		if callback != nil {
			callback(m.GetResult())
		}

		// Wait for next interval
		select {
		case <-ctx.Done():
			m.result.Duration = time.Since(m.result.StartTime)
			m.result.TotalCycles = cycle
			return nil
		case <-time.After(m.cfg.Interval):
		}
	}
}

func (m *MTR) runCycle(ctx context.Context, conn *icmp.PacketConn, pconn *ipv4.PacketConn, dst *net.IPAddr, cycle int) {
	// Send probes for all TTLs
	sentTimes := make(map[int]time.Time)

	for ttl := 1; ttl <= m.cfg.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pconn.SetTTL(ttl)

		seq := (cycle << 8) | ttl // Encode cycle and TTL in sequence

		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   m.pid,
				Seq:  seq,
				Data: []byte("NNS-MTR"),
			},
		}

		b, err := msg.Marshal(nil)
		if err != nil {
			continue
		}

		sentTimes[ttl] = time.Now()
		m.result.Hops[ttl-1].mu.Lock()
		m.result.Hops[ttl-1].Sent++
		m.result.Hops[ttl-1].mu.Unlock()

		conn.WriteTo(b, dst)
		time.Sleep(10 * time.Millisecond) // Small delay between probes
	}

	// Receive replies with timeout
	deadline := time.Now().Add(m.cfg.Timeout)
	conn.SetReadDeadline(deadline)

	buf := make([]byte, 1500)
	responded := make(map[int]bool)

	for time.Now().Before(deadline) {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		recvTime := time.Now()

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		var ttl int
		var peerIP string

		if addr, ok := peer.(*net.IPAddr); ok {
			peerIP = addr.String()
		}

		switch msg.Type {
		case ipv4.ICMPTypeTimeExceeded:
			body, ok := msg.Body.(*icmp.TimeExceeded)
			if !ok || len(body.Data) < 28 {
				continue
			}
			// Extract TTL from inner packet
			ihl := body.Data[0] & 0x0f
			headerLen := int(ihl) * 4
			if len(body.Data) < headerLen+8 {
				continue
			}
			innerICMP := body.Data[headerLen:]
			id := int(innerICMP[4])<<8 | int(innerICMP[5])
			if id != m.pid {
				continue
			}
			seq := int(innerICMP[6])<<8 | int(innerICMP[7])
			ttl = seq & 0xFF

		case ipv4.ICMPTypeEchoReply:
			body, ok := msg.Body.(*icmp.Echo)
			if !ok || body.ID != m.pid {
				continue
			}
			ttl = body.Seq & 0xFF

		default:
			continue
		}

		if ttl < 1 || ttl > m.cfg.MaxHops {
			continue
		}

		if responded[ttl] {
			continue
		}
		responded[ttl] = true

		sentTime, ok := sentTimes[ttl]
		if !ok {
			continue
		}

		rtt := recvTime.Sub(sentTime)
		hop := m.result.Hops[ttl-1]

		hop.mu.Lock()
		hop.Received++
		hop.LastRTT = rtt
		hop.AllRTTs = append(hop.AllRTTs, rtt)
		if hop.IP == "" || hop.IP != peerIP {
			hop.IP = peerIP
			if m.cfg.ResolveHost {
				if names, err := net.LookupAddr(peerIP); err == nil && len(names) > 0 {
					hop.Hostname = names[0]
				}
			}
		}
		hop.mu.Unlock()

		// Check if we reached destination
		if peerIP == dst.String() {
			break
		}
	}

	// Update stats for all hops
	for _, hop := range m.result.Hops {
		hop.mu.Lock()
		hop.Lost = hop.Sent - hop.Received
		if hop.Sent > 0 {
			hop.LossPercent = float64(hop.Lost) / float64(hop.Sent) * 100
		}
		if len(hop.AllRTTs) > 0 {
			hop.MinRTT, hop.MaxRTT, hop.AvgRTT, hop.StdDev = calculateStats(hop.AllRTTs)
		}
		hop.mu.Unlock()
	}
}

// GetResult returns a copy of the current result.
func (m *MTR) GetResult() *Result {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy
	result := &Result{
		Target:      m.result.Target,
		ResolvedIP:  m.result.ResolvedIP,
		TotalCycles: m.result.TotalCycles,
		StartTime:   m.result.StartTime,
		Duration:    m.result.Duration,
		Hops:        make([]*HopStats, len(m.result.Hops)),
	}

	for i, hop := range m.result.Hops {
		hop.mu.Lock()
		result.Hops[i] = &HopStats{
			TTL:         hop.TTL,
			IP:          hop.IP,
			Hostname:    hop.Hostname,
			Sent:        hop.Sent,
			Received:    hop.Received,
			Lost:        hop.Lost,
			LossPercent: hop.LossPercent,
			LastRTT:     hop.LastRTT,
			AvgRTT:      hop.AvgRTT,
			MinRTT:      hop.MinRTT,
			MaxRTT:      hop.MaxRTT,
			StdDev:      hop.StdDev,
		}
		hop.mu.Unlock()
	}

	return result
}

// GetActiveHops returns only hops that have responded.
func (r *Result) GetActiveHops() []*HopStats {
	active := make([]*HopStats, 0)
	for _, hop := range r.Hops {
		if hop.IP != "" {
			active = append(active, hop)
		}
	}
	return active
}

func calculateStats(rtts []time.Duration) (min, max, avg, stddev time.Duration) {
	if len(rtts) == 0 {
		return
	}

	sorted := make([]time.Duration, len(rtts))
	copy(sorted, rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	min = sorted[0]
	max = sorted[len(sorted)-1]

	var sum time.Duration
	for _, rtt := range rtts {
		sum += rtt
	}
	avg = sum / time.Duration(len(rtts))

	if len(rtts) > 1 {
		var sumSquares float64
		avgFloat := float64(avg)
		for _, rtt := range rtts {
			diff := float64(rtt) - avgFloat
			sumSquares += diff * diff
		}
		variance := sumSquares / float64(len(rtts))
		stddev = time.Duration(sqrt(variance))
	}

	return
}

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

// ParseTarget validates and returns the target.
func ParseTarget(target string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("target cannot be empty")
	}

	// Try to resolve
	_, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return "", fmt.Errorf("invalid target: %w", err)
	}

	return target, nil
}
