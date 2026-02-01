// Package wakewait provides Wake-on-LAN with active monitoring for host availability.
package wakewait

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Status represents the current state of the wake operation.
type Status string

const (
	StatusPending Status = "pending"
	StatusWaking  Status = "waking"
	StatusOnline  Status = "online"
	StatusTimeout Status = "timeout"
	StatusError   Status = "error"
)

// Result contains the outcome of a wake-and-wait operation.
type Result struct {
	MAC       string
	IP        string
	Status    Status
	WolSentAt time.Time
	OnlineAt  time.Time
	WakeTime  time.Duration
	Attempts  int
	LastCheck time.Time
	Error     error
}

// Config holds configuration for wake-and-wait operations.
type Config struct {
	BroadcastAddr string        // Broadcast address for WoL packet
	WolPort       int           // UDP port for WoL (default 9)
	CheckInterval time.Duration // How often to check if host is online
	Timeout       time.Duration // Maximum time to wait for host
	TCPPort       int           // Port to check for connectivity (default 22)
	PingMode      bool          // Use ICMP ping instead of TCP
	RetryWol      int           // Number of WoL retries if host doesn't respond
	RetryInterval time.Duration // Time between WoL retries
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		BroadcastAddr: "255.255.255.255",
		WolPort:       9,
		CheckInterval: 2 * time.Second,
		Timeout:       5 * time.Minute,
		TCPPort:       22,
		PingMode:      false,
		RetryWol:      3,
		RetryInterval: 30 * time.Second,
	}
}

// Client provides Wake-on-LAN with wait functionality.
type Client struct {
	config  Config
	onEvent func(Result)
	mu      sync.Mutex
}

// NewClient creates a new wake-wait client.
func NewClient(cfg Config) *Client {
	return &Client{config: cfg}
}

// OnEvent sets a callback for status updates.
func (c *Client) OnEvent(fn func(Result)) {
	c.mu.Lock()
	c.onEvent = fn
	c.mu.Unlock()
}

// WakeAndWait sends a WoL packet and waits for the host to come online.
func (c *Client) WakeAndWait(ctx context.Context, mac, targetIP string) (*Result, error) {
	result := &Result{
		MAC:       mac,
		IP:        targetIP,
		Status:    StatusPending,
		WolSentAt: time.Now(),
	}

	// Parse MAC address
	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("invalid MAC address: %w", err)
		return result, result.Error
	}

	// Create magic packet
	magicPacket := createMagicPacket(hwAddr)

	// Resolve broadcast address
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.config.BroadcastAddr, c.config.WolPort))
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("resolve address: %w", err)
		return result, result.Error
	}

	// Send initial WoL packet
	if err := c.sendWoL(magicPacket, addr); err != nil {
		result.Status = StatusError
		result.Error = err
		return result, err
	}

	result.Status = StatusWaking
	result.Attempts = 1
	c.notify(*result)

	// Start monitoring
	ticker := time.NewTicker(c.config.CheckInterval)
	defer ticker.Stop()

	retryTicker := time.NewTicker(c.config.RetryInterval)
	defer retryTicker.Stop()

	timeout := time.After(c.config.Timeout)
	wolRetries := 0

	for {
		select {
		case <-ctx.Done():
			result.Status = StatusError
			result.Error = ctx.Err()
			return result, ctx.Err()

		case <-timeout:
			result.Status = StatusTimeout
			result.Error = fmt.Errorf("timeout waiting for host after %v", c.config.Timeout)
			c.notify(*result)
			return result, result.Error

		case <-ticker.C:
			result.LastCheck = time.Now()

			if c.isHostOnline(ctx, targetIP) {
				result.Status = StatusOnline
				result.OnlineAt = time.Now()
				result.WakeTime = result.OnlineAt.Sub(result.WolSentAt)
				c.notify(*result)
				return result, nil
			}

		case <-retryTicker.C:
			if wolRetries < c.config.RetryWol {
				wolRetries++
				result.Attempts++
				if err := c.sendWoL(magicPacket, addr); err == nil {
					c.notify(*result)
				}
			}
		}
	}
}

func (c *Client) sendWoL(packet []byte, addr *net.UDPAddr) error {
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("dial UDP: %w", err)
	}
	defer conn.Close()

	// Set socket options for broadcast
	if err := conn.SetWriteBuffer(len(packet)); err != nil {
		// Non-fatal, continue anyway
	}

	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("send packet: %w", err)
	}

	return nil
}

func (c *Client) isHostOnline(ctx context.Context, ip string) bool {
	if c.config.PingMode {
		return c.pingCheck(ctx, ip)
	}
	return c.tcpCheck(ctx, ip)
}

func (c *Client) tcpCheck(ctx context.Context, ip string) bool {
	addr := fmt.Sprintf("%s:%d", ip, c.config.TCPPort)

	d := net.Dialer{Timeout: c.config.CheckInterval / 2}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (c *Client) pingCheck(ctx context.Context, ip string) bool {
	// Simple ICMP ping implementation
	// For full ping, use the existing ping package
	conn, err := net.DialTimeout("ip4:icmp", ip, c.config.CheckInterval/2)
	if err != nil {
		// Fallback to TCP if ICMP not available (requires admin)
		return c.tcpCheck(ctx, ip)
	}
	conn.Close()
	return true
}

func (c *Client) notify(result Result) {
	c.mu.Lock()
	fn := c.onEvent
	c.mu.Unlock()

	if fn != nil {
		fn(result)
	}
}

// createMagicPacket creates a Wake-on-LAN magic packet.
func createMagicPacket(mac net.HardwareAddr) []byte {
	// Magic packet: 6 bytes of 0xFF followed by MAC address repeated 16 times
	packet := make([]byte, 102)

	// 6 bytes of 0xFF
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}

	// MAC address repeated 16 times
	for i := 0; i < 16; i++ {
		copy(packet[6+i*6:], mac)
	}

	return packet
}

// ParseMAC parses various MAC address formats.
func ParseMAC(s string) (net.HardwareAddr, error) {
	return net.ParseMAC(s)
}

// WakeMultiple wakes multiple hosts concurrently and waits for all.
func (c *Client) WakeMultiple(ctx context.Context, hosts map[string]string) map[string]*Result {
	results := make(map[string]*Result)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for mac, ip := range hosts {
		wg.Add(1)
		go func(mac, ip string) {
			defer wg.Done()
			result, _ := c.WakeAndWait(ctx, mac, ip)
			mu.Lock()
			results[mac] = result
			mu.Unlock()
		}(mac, ip)
	}

	wg.Wait()
	return results
}

// QuickWake sends a WoL packet without waiting.
func QuickWake(mac string, broadcastAddr string) error {
	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC: %w", err)
	}

	if broadcastAddr == "" {
		broadcastAddr = "255.255.255.255"
	}

	addr, err := net.ResolveUDPAddr("udp4", broadcastAddr+":9")
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(createMagicPacket(hwAddr))
	return err
}
