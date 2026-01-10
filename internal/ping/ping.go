// Package ping provides enhanced ICMP ping functionality with advanced statistics.
package ping

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpProtocol is the protocol number for ICMPv4.
const icmpProtocol = 1

// PingResult represents the result of a single ping.
type PingResult struct {
	Seq     int
	RTT     time.Duration
	TTL     int
	Success bool
	Error   error
}

// Pinger configures and executes ping operations.
type Pinger struct {
	Host       string
	ResolvedIP string
	Count      int           // Number of pings (0 = infinite)
	Interval   time.Duration // Time between pings
	Timeout    time.Duration // Timeout per ping
	PacketSize int           // Size of ICMP packet data
	Stats      *Statistics

	conn *icmp.PacketConn
	id   int
}

// NewPinger creates a new Pinger with default settings.
func NewPinger(host string) *Pinger {
	return &Pinger{
		Host:       host,
		Count:      0, // Infinite by default
		Interval:   1 * time.Second,
		Timeout:    4 * time.Second,
		PacketSize: 64,
		Stats:      NewStatistics(),
		id:         os.Getpid() & 0xffff, // Use process ID as identifier
	}
}

// Resolve performs DNS resolution for the target host.
func (p *Pinger) Resolve() error {
	// Try to parse as IP first
	if ip := net.ParseIP(p.Host); ip != nil {
		p.ResolvedIP = ip.String()
		return nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(p.Host)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %v", p.Host, err)
	}

	// Use first IPv4 address
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			p.ResolvedIP = ipv4.String()
			return nil
		}
	}

	return fmt.Errorf("no IPv4 address found for %s", p.Host)
}

// ReverseDNS performs reverse DNS lookup.
func (p *Pinger) ReverseDNS() (string, error) {
	names, err := net.LookupAddr(p.ResolvedIP)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return names[0], nil
}

// Run executes the ping sequence.
func (p *Pinger) Run(ctx context.Context, callback func(PingResult)) error {
	// Open ICMP connection
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("failed to open ICMP connection (try running as administrator): %v", err)
	}
	defer conn.Close()
	p.conn = conn

	// Parse destination address
	dst, err := net.ResolveIPAddr("ip4", p.ResolvedIP)
	if err != nil {
		return fmt.Errorf("failed to resolve IP address: %v", err)
	}

	// Wrapper callback that updates statistics
	wrappedCallback := func(result PingResult) {
		if result.Success {
			p.Stats.AddRTT(result.RTT)
		} else {
			p.Stats.AddLost()
		}
		callback(result)
	}

	seq := 1
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()

	// Send first ping immediately
	result := p.sendOne(dst, seq)
	wrappedCallback(result)
	seq++

	for {
		select {
		case <-ctx.Done():
			p.Stats.Calculate()
			return nil
		case <-ticker.C:
			if p.Count > 0 && seq > p.Count {
				p.Stats.Calculate()
				return nil
			}

			result := p.sendOne(dst, seq)
			wrappedCallback(result)
			seq++
		}
	}
}

// sendOne sends a single ICMP echo request and waits for reply.
func (p *Pinger) sendOne(dst *net.IPAddr, seq int) PingResult {
	result := PingResult{
		Seq:     seq,
		Success: false,
	}

	// Create ICMP echo request
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  seq,
			Data: make([]byte, p.PacketSize),
		},
	}

	// Marshal message
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		result.Error = fmt.Errorf("failed to marshal ICMP message: %v", err)
		return result
	}

	// Send packet
	start := time.Now()
	_, err = p.conn.WriteTo(msgBytes, dst)
	if err != nil {
		result.Error = fmt.Errorf("failed to send packet: %v", err)
		return result
	}

	// Wait for reply
	reply := make([]byte, 1500)
	if err := p.conn.SetReadDeadline(time.Now().Add(p.Timeout)); err != nil {
		result.Error = fmt.Errorf("failed to set read deadline: %v", err)
		return result
	}

	for {
		n, peer, err := p.conn.ReadFrom(reply)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.Error = fmt.Errorf("timeout")
			} else {
				result.Error = fmt.Errorf("read error: %v", err)
			}
			return result
		}

		// Parse ICMP message
		replyMsg, err := icmp.ParseMessage(icmpProtocol, reply[:n])
		if err != nil {
			continue // Not a valid ICMP message
		}

		// Check if it's an echo reply
		if replyMsg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		// Extract echo reply body
		echoReply, ok := replyMsg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		// Check if this reply is for us
		if echoReply.ID != p.id || echoReply.Seq != seq {
			continue // Not our packet
		}

		// Check source matches destination
		if peer.String() != dst.String() {
			continue
		}

		// Calculate RTT
		rtt := time.Since(start)

		result.RTT = rtt
		result.TTL = getTTL(reply)
		result.Success = true

		return result
	}
}

// getTTL extracts TTL from IP header.
func getTTL(data []byte) int {
	if len(data) < 9 {
		return 0
	}
	return int(data[8]) // TTL is at byte 8 in IPv4 header
}
