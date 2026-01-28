// Package pcap provides simplified packet capture and analysis
package pcap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Packet represents a captured network packet
type Packet struct {
	Timestamp   time.Time
	Length      int
	Protocol    string
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     int
	DstPort     int
	Flags       string
	PayloadSize int
	Info        string
}

// Stats holds capture statistics
type Stats struct {
	PacketsCaptured uint64
	BytesCaptured   uint64
	PacketsDropped  uint64
	StartTime       time.Time
	Duration        time.Duration
	ProtocolCounts  map[string]uint64
}

// Filter defines packet filtering criteria
type Filter struct {
	Protocol string // tcp, udp, icmp, or empty for all
	SrcHost  string // source IP/hostname filter
	DstHost  string // destination IP/hostname filter
	Port     int    // port filter (src or dst)
	SrcPort  int    // specific source port
	DstPort  int    // specific destination port
	MinSize  int    // minimum packet size
	MaxSize  int    // maximum packet size (0 = no limit)
}

// CaptureOptions configures packet capture
type CaptureOptions struct {
	Interface   string        // network interface name
	Filter      Filter        // packet filter
	SnapLen     int           // snapshot length (bytes to capture per packet)
	Promiscuous bool          // promiscuous mode
	Timeout     time.Duration // read timeout
	MaxPackets  int           // max packets to capture (0 = unlimited)
	MaxDuration time.Duration // max capture duration (0 = unlimited)
}

// DefaultOptions returns sensible default capture options
func DefaultOptions() CaptureOptions {
	return CaptureOptions{
		SnapLen:     65535,
		Promiscuous: false,
		Timeout:     time.Second,
		MaxPackets:  0,
		MaxDuration: 0,
	}
}

// PacketHandler is called for each captured packet
type PacketHandler func(pkt Packet)

// Capture represents an active packet capture session
type Capture struct {
	opts      CaptureOptions
	stats     Stats
	mu        sync.RWMutex
	running   atomic.Bool
	packets   []Packet
	handler   PacketHandler
	stopChan  chan struct{}
	startTime time.Time
}

// NewCapture creates a new packet capture session
func NewCapture(opts CaptureOptions) (*Capture, error) {
	if opts.Interface == "" {
		// Try to find default interface
		iface, err := getDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("no interface specified and couldn't find default: %w", err)
		}
		opts.Interface = iface
	}

	// Validate interface exists
	if _, err := net.InterfaceByName(opts.Interface); err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", opts.Interface, err)
	}

	if opts.SnapLen <= 0 {
		opts.SnapLen = 65535
	}

	return &Capture{
		opts:     opts,
		stopChan: make(chan struct{}),
		stats: Stats{
			ProtocolCounts: make(map[string]uint64),
		},
	}, nil
}

// SetHandler sets the packet handler callback
func (c *Capture) SetHandler(handler PacketHandler) {
	c.handler = handler
}

// Start begins packet capture
func (c *Capture) Start(ctx context.Context) error {
	if c.running.Load() {
		return fmt.Errorf("capture already running")
	}

	c.running.Store(true)
	c.startTime = time.Now()
	c.stats.StartTime = c.startTime

	go c.captureLoop(ctx)
	return nil
}

// Stop ends packet capture
func (c *Capture) Stop() {
	if c.running.Load() {
		c.running.Store(false)
		close(c.stopChan)
	}
}

// IsRunning returns whether capture is active
func (c *Capture) IsRunning() bool {
	return c.running.Load()
}

// Stats returns current capture statistics
func (c *Capture) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.Duration = time.Since(c.startTime)
	return stats
}

// Packets returns all captured packets
func (c *Capture) Packets() []Packet {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]Packet, len(c.packets))
	copy(result, c.packets)
	return result
}

// captureLoop simulates packet capture (real implementation would use libpcap)
func (c *Capture) captureLoop(ctx context.Context) {
	defer c.running.Store(false)

	// In a real implementation, this would use libpcap/npcap
	// For now, we simulate by monitoring network connections
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var packetCount int

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			// Simulate packet capture based on active connections
			packets := c.simulateCapture()
			for _, pkt := range packets {
				if c.matchesFilter(pkt) {
					c.recordPacket(pkt)
					packetCount++

					if c.opts.MaxPackets > 0 && packetCount >= c.opts.MaxPackets {
						return
					}
				}
			}

			if c.opts.MaxDuration > 0 && time.Since(c.startTime) >= c.opts.MaxDuration {
				return
			}
		}
	}
}

// simulateCapture creates simulated packets based on system state
func (c *Capture) simulateCapture() []Packet {
	// This is a simulation - real implementation would use raw sockets or libpcap
	var packets []Packet

	// Get active connections for simulation
	conns := getActiveConnections()
	now := time.Now()

	for _, conn := range conns {
		pkt := Packet{
			Timestamp:   now,
			Length:      conn.size,
			Protocol:    conn.protocol,
			SrcIP:       conn.srcIP,
			DstIP:       conn.dstIP,
			SrcPort:     conn.srcPort,
			DstPort:     conn.dstPort,
			PayloadSize: conn.size - 40, // simulate header subtraction
			Info:        conn.info,
		}
		packets = append(packets, pkt)
	}

	return packets
}

// matchesFilter checks if a packet matches the capture filter
func (c *Capture) matchesFilter(pkt Packet) bool {
	f := c.opts.Filter

	// Protocol filter
	if f.Protocol != "" && !strings.EqualFold(pkt.Protocol, f.Protocol) {
		return false
	}

	// Source host filter
	if f.SrcHost != "" {
		srcIP := net.ParseIP(f.SrcHost)
		if srcIP != nil && !pkt.SrcIP.Equal(srcIP) {
			return false
		}
	}

	// Destination host filter
	if f.DstHost != "" {
		dstIP := net.ParseIP(f.DstHost)
		if dstIP != nil && !pkt.DstIP.Equal(dstIP) {
			return false
		}
	}

	// Port filters
	if f.Port > 0 && pkt.SrcPort != f.Port && pkt.DstPort != f.Port {
		return false
	}
	if f.SrcPort > 0 && pkt.SrcPort != f.SrcPort {
		return false
	}
	if f.DstPort > 0 && pkt.DstPort != f.DstPort {
		return false
	}

	// Size filters
	if f.MinSize > 0 && pkt.Length < f.MinSize {
		return false
	}
	if f.MaxSize > 0 && pkt.Length > f.MaxSize {
		return false
	}

	return true
}

// recordPacket stores a captured packet
func (c *Capture) recordPacket(pkt Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.packets = append(c.packets, pkt)
	c.stats.PacketsCaptured++
	c.stats.BytesCaptured += uint64(pkt.Length)
	c.stats.ProtocolCounts[pkt.Protocol]++

	if c.handler != nil {
		c.handler(pkt)
	}
}

// Format returns a human-readable string for a packet
func (pkt Packet) Format() string {
	return fmt.Sprintf("%s %s %s:%d → %s:%d len=%d %s",
		pkt.Timestamp.Format("15:04:05.000"),
		pkt.Protocol,
		pkt.SrcIP, pkt.SrcPort,
		pkt.DstIP, pkt.DstPort,
		pkt.Length,
		pkt.Info,
	)
}

// FormatStats returns formatted capture statistics
func (s Stats) Format() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Capture Statistics\n"))
	sb.WriteString(fmt.Sprintf("  Duration:        %v\n", s.Duration.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("  Packets:         %d\n", s.PacketsCaptured))
	sb.WriteString(fmt.Sprintf("  Bytes:           %d\n", s.BytesCaptured))
	if s.PacketsDropped > 0 {
		sb.WriteString(fmt.Sprintf("  Dropped:         %d\n", s.PacketsDropped))
	}
	if len(s.ProtocolCounts) > 0 {
		sb.WriteString("  Protocols:\n")
		for proto, count := range s.ProtocolCounts {
			sb.WriteString(fmt.Sprintf("    %-10s %d\n", proto, count))
		}
	}
	return sb.String()
}

// ListInterfaces returns available network interfaces for capture
func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue // skip loopback
		}

		info := InterfaceInfo{
			Name:  iface.Name,
			Index: iface.Index,
			MTU:   iface.MTU,
			Flags: iface.Flags.String(),
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			info.Addresses = append(info.Addresses, addr.String())
		}

		result = append(result, info)
	}

	return result, nil
}

// InterfaceInfo holds interface details
type InterfaceInfo struct {
	Name      string
	Index     int
	MTU       int
	Flags     string
	Addresses []string
}

// getDefaultInterface finds the default network interface
func getDefaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no suitable interface found")
}

// connectionInfo for simulation
type connectionInfo struct {
	protocol string
	srcIP    net.IP
	dstIP    net.IP
	srcPort  int
	dstPort  int
	size     int
	info     string
}

// getActiveConnections simulates getting active connections
func getActiveConnections() []connectionInfo {
	// Simulation - in reality would capture actual packets
	return []connectionInfo{
		{
			protocol: "TCP",
			srcIP:    net.ParseIP("192.168.1.100"),
			dstIP:    net.ParseIP("8.8.8.8"),
			srcPort:  52341,
			dstPort:  443,
			size:     1500,
			info:     "HTTPS",
		},
	}
}
