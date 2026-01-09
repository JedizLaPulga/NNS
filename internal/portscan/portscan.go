// Package portscan provides port scanning functionality.
package portscan

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult represents the result of scanning a single port.
type ScanResult struct {
	Host   string
	Port   int
	Open   bool
	Banner string // Service banner if available
	Error  error
}

// Scanner configures port scanning behavior.
type Scanner struct {
	Timeout     time.Duration
	Concurrency int
}

// NewScanner creates a new Scanner with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		Timeout:     2 * time.Second,
		Concurrency: 100,
	}
}

// ScanPort scans a single port on the specified host.
func ScanPort(host string, port int, timeout time.Duration) ScanResult {
	result := ScanResult{
		Host: host,
		Port: port,
		Open: false,
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)

	if err != nil {
		// Port is closed or unreachable
		result.Error = err
		return result
	}

	result.Open = true

	// Try to grab banner
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	banner := make([]byte, 1024)
	n, _ := conn.Read(banner)
	if n > 0 {
		result.Banner = strings.TrimSpace(string(banner[:n]))
	}

	conn.Close()
	return result
}

// ScanPorts scans multiple ports on a host using concurrent workers.
func (s *Scanner) ScanPorts(host string, ports []int) []ScanResult {
	results := make([]ScanResult, 0, len(ports))
	resultsChan := make(chan ScanResult, len(ports))
	portsChan := make(chan int, len(ports))

	var wg sync.WaitGroup

	// Start worker pool
	numWorkers := s.Concurrency
	if numWorkers > len(ports) {
		numWorkers = len(ports)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				result := ScanPort(host, port, s.Timeout)
				resultsChan <- result
			}
		}()
	}

	// Send ports to workers
	go func() {
		for _, port := range ports {
			portsChan <- port
		}
		close(portsChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	// Sort results by port number for consistent output
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

// ParsePortRange parses a port specification like "80,443,8000-8080" into a slice of port numbers.
func ParsePortRange(input string) ([]int, error) {
	if input == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	ports := make(map[int]bool) // Use map to avoid duplicates
	parts := strings.Split(input, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Handle range (e.g., "8000-8080")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range %s: %v", part, err)
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range %s: %v", part, err)
			}

			if start > end {
				return nil, fmt.Errorf("invalid port range: start (%d) > end (%d)", start, end)
			}

			if start < 1 || end > 65535 {
				return nil, fmt.Errorf("port range must be between 1 and 65535")
			}

			for p := start; p <= end; p++ {
				ports[p] = true
			}
		} else {
			// Handle single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port must be between 1 and 65535: %d", port)
			}

			ports[port] = true
		}
	}

	// Convert map to sorted slice
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)

	return result, nil
}

// ParseCIDR parses a CIDR notation (e.g., "192.168.1.0/24") and returns a slice of host IPs.
func ParseCIDR(cidr string) ([]string, error) {
	// Handle single IP (no CIDR notation)
	if !strings.Contains(cidr, "/") {
		// Validate it's a valid IP or hostname
		ip := net.ParseIP(cidr)
		if ip == nil {
			// Might be a hostname, return as-is
			return []string{cidr}, nil
		}
		return []string{cidr}, nil
	}

	// Parse CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %v", err)
	}

	hosts := make([]string, 0)

	// Iterate through all IPs in the network
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		// Skip network and broadcast addresses for typical subnets
		if !isNetworkOrBroadcast(ip, ipNet) {
			hosts = append(hosts, ip.String())
		}
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

// isNetworkOrBroadcast checks if an IP is the network or broadcast address.
func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	// Network address
	if ip.Equal(ipNet.IP) {
		return true
	}

	// Broadcast address (all host bits set)
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}

	return ip.Equal(broadcast)
}

// CommonPorts returns a list of commonly scanned ports.
func CommonPorts() []int {
	return []int{
		21,   // FTP
		22,   // SSH
		23,   // Telnet
		25,   // SMTP
		53,   // DNS
		80,   // HTTP
		110,  // POP3
		143,  // IMAP
		443,  // HTTPS
		445,  // SMB
		3306, // MySQL
		3389, // RDP
		5432, // PostgreSQL
		6379, // Redis
		8080, // HTTP Alt
		8443, // HTTPS Alt
	}
}
