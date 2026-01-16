// Package sweep provides network host discovery functionality.
package sweep

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// HostResult represents the result of probing a single host.
type HostResult struct {
	IP       string
	Alive    bool
	Hostname string
	Latency  time.Duration
	Method   string
	Port     int // For TCP method, which port responded
	Error    error
}

// Config configures the sweep operation.
type Config struct {
	CIDR        string
	Timeout     time.Duration
	Concurrency int
	Method      string // "icmp" or "tcp"
	Ports       []int  // Ports to check for TCP method
	Resolve     bool   // Resolve hostnames
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:     1 * time.Second,
		Concurrency: 256,
		Method:      "tcp",
		Ports:       []int{80, 443, 22, 445, 139, 3389},
		Resolve:     true,
	}
}

// Sweeper performs network host discovery.
type Sweeper struct {
	Config Config
}

// NewSweeper creates a new Sweeper with the given configuration.
func NewSweeper(cfg Config) *Sweeper {
	return &Sweeper{Config: cfg}
}

// Sweep scans the configured CIDR range for live hosts.
// It calls the callback for each discovered host.
func (s *Sweeper) Sweep(ctx context.Context, callback func(HostResult)) ([]HostResult, error) {
	hosts, err := ParseCIDR(s.Config.CIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	results := make([]HostResult, 0)
	resultsChan := make(chan HostResult, len(hosts))
	hostsChan := make(chan string, len(hosts))

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Start workers
	numWorkers := s.Config.Concurrency
	if numWorkers > len(hosts) {
		numWorkers = len(hosts)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range hostsChan {
				select {
				case <-ctx.Done():
					return
				default:
					result := s.probeHost(ctx, ip)
					resultsChan <- result
				}
			}
		}()
	}

	// Send hosts to workers
	go func() {
	HostLoop:
		for _, ip := range hosts {
			select {
			case <-ctx.Done():
				break HostLoop
			case hostsChan <- ip:
			}
		}
		close(hostsChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		if callback != nil && result.Alive {
			callback(result)
		}
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	}

	// Sort by IP for consistent output
	sort.Slice(results, func(i, j int) bool {
		return compareIPs(results[i].IP, results[j].IP) < 0
	})

	return results, nil
}

// probeHost checks if a single host is alive.
func (s *Sweeper) probeHost(ctx context.Context, ip string) HostResult {
	result := HostResult{
		IP:     ip,
		Alive:  false,
		Method: s.Config.Method,
	}

	switch s.Config.Method {
	case "tcp":
		result = s.probeTCP(ctx, ip)
	default:
		// Default to TCP since ICMP requires admin privileges
		result = s.probeTCP(ctx, ip)
	}

	// Resolve hostname if alive and resolution enabled
	if result.Alive && s.Config.Resolve {
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			result.Hostname = names[0]
		}
	}

	return result
}

// probeTCP attempts to connect to common ports on the target.
func (s *Sweeper) probeTCP(ctx context.Context, ip string) HostResult {
	result := HostResult{
		IP:     ip,
		Alive:  false,
		Method: "tcp",
	}

	ports := s.Config.Ports
	if len(ports) == 0 {
		ports = []int{80, 443, 22}
	}

	// Try each port until one succeeds
	for _, port := range ports {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result
		default:
		}

		start := time.Now()
		addr := fmt.Sprintf("%s:%d", ip, port)

		// Use DialContext for timeout and cancellation
		d := net.Dialer{Timeout: s.Config.Timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)

		if err == nil {
			result.Alive = true
			result.Latency = time.Since(start)
			result.Port = port
			conn.Close()
			return result
		}
	}

	return result
}

// ParseCIDR parses a CIDR notation and returns all host IPs.
func ParseCIDR(cidr string) ([]string, error) {
	// Handle single IP
	if ip := net.ParseIP(cidr); ip != nil {
		return []string{cidr}, nil
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, 0)
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	for ; ipNet.Contains(ip); incIP(ip) {
		// Skip network and broadcast for /24 and smaller
		ones, bits := ipNet.Mask.Size()
		if bits-ones <= 8 {
			if isNetworkOrBroadcast(ip, ipNet) {
				continue
			}
		}
		hosts = append(hosts, ip.String())
	}

	return hosts, nil
}

// incIP increments an IP address.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isNetworkOrBroadcast checks if an IP is network or broadcast address.
func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	if ip.Equal(ipNet.IP) {
		return true
	}

	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	return ip.Equal(broadcast)
}

// compareIPs compares two IP address strings.
func compareIPs(a, b string) int {
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)

	if ipA == nil || ipB == nil {
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}

	// Normalize to 16-byte representation
	ipA = ipA.To16()
	ipB = ipB.To16()

	for i := 0; i < len(ipA); i++ {
		if ipA[i] < ipB[i] {
			return -1
		}
		if ipA[i] > ipB[i] {
			return 1
		}
	}
	return 0
}

// GetAliveHosts filters results to return only alive hosts.
func GetAliveHosts(results []HostResult) []HostResult {
	alive := make([]HostResult, 0)
	for _, r := range results {
		if r.Alive {
			alive = append(alive, r)
		}
	}
	return alive
}

// CountHosts returns the number of hosts in a CIDR range.
func CountHosts(cidr string) (int, error) {
	hosts, err := ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	return len(hosts), nil
}
