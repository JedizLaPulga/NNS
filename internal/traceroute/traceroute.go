// Package traceroute provides advanced network path discovery.
package traceroute

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Hop represents a single router/node in the path.
type Hop struct {
	TTL         int
	IP          string
	Hosts       []string
	ASN         string // e.g. "AS15169"
	Org         string // e.g. "Google LLC"
	RTTs        []time.Duration
	ReachedDest bool
	Timeout     bool
	ProbesSent  int
}

// Config for the Tracer.
type Config struct {
	Target    string
	MaxHops   int
	Queries   int // Probes per hop
	Timeout   time.Duration
	ResolveAS bool
}

// Tracer executes the traceroute.
type Tracer struct {
	cfg       Config
	pid       int
	sentTimes map[int]time.Time // Seq -> SendTime
	mu        sync.Mutex
}

// NewTracer creates a new Tracer.
func NewTracer(cfg Config) *Tracer {
	if cfg.MaxHops == 0 {
		cfg.MaxHops = 30
	}
	if cfg.Queries == 0 {
		cfg.Queries = 3
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}

	return &Tracer{
		cfg:       cfg,
		pid:       os.Getpid() & 0xffff,
		sentTimes: make(map[int]time.Time),
	}
}

// Run executes the trace.
func (t *Tracer) Run(ctx context.Context, callback func(h *Hop)) error {
	dstIP, err := net.ResolveIPAddr("ip4", t.cfg.Target)
	if err != nil {
		return fmt.Errorf("resolve failed: %w", err)
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("listen failed (needs admin): %w", err)
	}
	defer c.Close()

	pconn := c.IPv4PacketConn()

	// Pre-allocate Hops
	hops := make([]*Hop, t.cfg.MaxHops)
	for i := 0; i < t.cfg.MaxHops; i++ {
		hops[i] = &Hop{TTL: i + 1, RTTs: make([]time.Duration, 0)}
	}

	// Receiver Channel
	packets := make(chan *icmpMessage, 100)

	// Start Receiver
	go func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, peer, err := c.ReadFrom(buf)
				if err != nil {
					continue
				}

				m, err := icmp.ParseMessage(1, buf[:n])
				if err != nil {
					continue
				}

				packets <- &icmpMessage{Msg: m, Peer: peer, RecvTime: time.Now()}
			}
		}
	}()

	// Loop through TTLs
	for ttl := 1; ttl <= t.cfg.MaxHops; ttl++ {
		hop := hops[ttl-1]

		// Send Probes
		for q := 0; q < t.cfg.Queries; q++ {
			pconn.SetTTL(ttl)

			// Encode Seq: (TTL << 8) | queryIdx
			seq := (ttl << 8) | q

			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{
					ID: t.pid, Seq: seq,
					Data: []byte("NNS"),
				},
			}
			b, err := msg.Marshal(nil)
			if err != nil {
				log.Printf("traceroute: failed to marshal ICMP message: %v", err)
				continue
			}

			t.mu.Lock()
			t.sentTimes[seq] = time.Now()
			t.mu.Unlock()

			if _, err := c.WriteTo(b, dstIP); err != nil {
				log.Printf("traceroute: failed to send probe TTL=%d: %v", ttl, err)
			}
			hop.ProbesSent++
			time.Sleep(20 * time.Millisecond) // Inter-probe delay
		}

		// Wait for replies
		timeout := time.After(t.cfg.Timeout)

	ProbeLoop:
		for {
			select {
			case pkt := <-packets:
				t.processPacket(pkt, hops, dstIP.String())

				t.mu.Lock()
				currentDone := len(hop.RTTs) >= t.cfg.Queries
				t.mu.Unlock()

				if currentDone {
					break ProbeLoop
				}
				// Continue waiting for remaining probes even after reaching destination

			case <-timeout:
				break ProbeLoop
			case <-ctx.Done():
				return nil
			}
		}

		// Finalize Hop
		t.enrichHop(hop)
		callback(hop)

		if hop.ReachedDest {
			break
		}
	}

	return nil
}

type icmpMessage struct {
	Msg      *icmp.Message
	Peer     net.Addr
	RecvTime time.Time
}

func (t *Tracer) processPacket(pkt *icmpMessage, hops []*Hop, dstIP string) {
	var seq int
	var peerIP string

	if addr, ok := pkt.Peer.(*net.IPAddr); ok {
		peerIP = addr.String()
	} else if addr, ok := pkt.Peer.(*net.UDPAddr); ok {
		peerIP = addr.IP.String()
	} else {
		peerIP = pkt.Peer.String()
	}

	// Extract Original Seq
	switch pkt.Msg.Type {
	case ipv4.ICMPTypeTimeExceeded:
		body, ok := pkt.Msg.Body.(*icmp.TimeExceeded)
		if !ok || len(body.Data) < 28 {
			return
		}

		// Parse inner IP to skip
		ihl := body.Data[0] & 0x0f
		headerLen := int(ihl) * 4
		if len(body.Data) < headerLen+8 {
			return
		}

		innerICMP := body.Data[headerLen:]

		id := int(innerICMP[4])<<8 | int(innerICMP[5])
		if id != t.pid {
			return
		}
		seq = int(innerICMP[6])<<8 | int(innerICMP[7])

	case ipv4.ICMPTypeEchoReply:
		body, ok := pkt.Msg.Body.(*icmp.Echo)
		if !ok || body.ID != t.pid {
			return
		}
		seq = body.Seq

	default:
		return
	}

	// Decode Seq -> TTL
	ttl := seq >> 8
	if ttl < 1 || ttl > len(hops) {
		return
	}

	// Calc RTT
	t.mu.Lock()
	sent, ok := t.sentTimes[seq]
	t.mu.Unlock()

	if !ok {
		return
	} // Stray packet

	rtt := pkt.RecvTime.Sub(sent)

	hop := hops[ttl-1]

	t.mu.Lock()
	defer t.mu.Unlock()

	hop.RTTs = append(hop.RTTs, rtt)
	hop.IP = peerIP

	if pkt.Msg.Type == ipv4.ICMPTypeEchoReply {
		hop.ReachedDest = true
	}
	if peerIP == dstIP {
		hop.ReachedDest = true
	}
}

func (t *Tracer) enrichHop(h *Hop) {
	if h.IP == "" {
		h.Timeout = true
		return
	}

	// Resolve Hostname
	names, _ := net.LookupAddr(h.IP)
	if len(names) > 0 {
		h.Hosts = names
	}

	if t.cfg.ResolveAS {
		h.ASN, h.Org = LookupAS(h.IP)
	}
}

// LookupAS performs DNS-based AS lookup.
func LookupAS(ip string) (string, string) {
	// Revert IP: 1.2.3.4 -> 4.3.2.1
	parts := parseIP(ip)
	if parts == nil {
		return "", ""
	}

	query := fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com", parts[3], parts[2], parts[1], parts[0])

	txts, err := net.LookupTXT(query)
	if err != nil || len(txts) == 0 {
		return "", ""
	}

	// Format: "15169 | 8.8.8.0/24 | US | google | 2000-01-01"
	fields := strings.Split(txts[0], "|")
	if len(fields) >= 1 {
		asn := "AS" + strings.TrimSpace(fields[0])
		org := ""
		if len(fields) >= 4 {
			org = strings.TrimSpace(fields[3])
		}
		return asn, org
	}

	return "", ""
}

func parseIP(ip string) []string {
	p := net.ParseIP(ip)
	if p == nil {
		return nil
	}
	p4 := p.To4()
	if p4 == nil {
		return nil
	}
	return []string{
		fmt.Sprintf("%d", p4[0]),
		fmt.Sprintf("%d", p4[1]),
		fmt.Sprintf("%d", p4[2]),
		fmt.Sprintf("%d", p4[3]),
	}
}
