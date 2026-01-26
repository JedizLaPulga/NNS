// Package ssdp provides SSDP (Simple Service Discovery Protocol) discovery for UPnP devices.
package ssdp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// SSDPMulticastAddr is the standard SSDP multicast address.
	SSDPMulticastAddr = "239.255.255.250:1900"

	// DefaultSearchTarget searches for all devices.
	DefaultSearchTarget = "ssdp:all"

	// UPnPRootDevice searches for UPnP root devices only.
	UPnPRootDevice = "upnp:rootdevice"
)

// Device represents a discovered SSDP device.
type Device struct {
	Location     string            // URL to device description XML
	Server       string            // Server header
	USN          string            // Unique Service Name
	ST           string            // Search Target (device type)
	Headers      map[string]string // All headers
	IP           string            // Device IP address
	ResponseTime time.Duration     // Time to receive response
}

// Config holds SSDP discovery configuration.
type Config struct {
	Timeout      time.Duration // Discovery timeout
	SearchTarget string        // Device type to search for
	MX           int           // Maximum wait time for responses (in seconds)
	Interface    string        // Network interface to use (empty = all)
}

// DefaultConfig returns default discovery configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:      3 * time.Second,
		SearchTarget: DefaultSearchTarget,
		MX:           2,
	}
}

// Scanner performs SSDP discovery.
type Scanner struct {
	config Config
}

// New creates a new SSDP scanner.
func New(cfg Config) *Scanner {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.SearchTarget == "" {
		cfg.SearchTarget = DefaultSearchTarget
	}
	if cfg.MX <= 0 {
		cfg.MX = 2
	}
	return &Scanner{config: cfg}
}

// Discover performs SSDP discovery and returns found devices.
func (s *Scanner) Discover() ([]Device, error) {
	// Create UDP connection
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer conn.Close()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(s.config.Timeout)); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Create M-SEARCH request
	request := s.buildMSearchRequest()

	// Resolve multicast address
	addr, err := net.ResolveUDPAddr("udp4", SSDPMulticastAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve multicast address: %w", err)
	}

	// Send discovery request
	startTime := time.Now()
	_, err = conn.WriteToUDP([]byte(request), addr)
	if err != nil {
		return nil, fmt.Errorf("failed to send M-SEARCH: %w", err)
	}

	// Collect responses
	var devices []Device
	seen := make(map[string]bool) // Deduplicate by USN
	buf := make([]byte, 4096)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Timeout is expected
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return devices, err
		}

		device, err := parseResponse(buf[:n])
		if err != nil {
			continue // Skip malformed responses
		}

		device.IP = remoteAddr.IP.String()
		device.ResponseTime = time.Since(startTime)

		// Deduplicate
		if device.USN != "" && !seen[device.USN] {
			seen[device.USN] = true
			devices = append(devices, device)
		} else if device.USN == "" && device.Location != "" && !seen[device.Location] {
			seen[device.Location] = true
			devices = append(devices, device)
		}
	}

	return devices, nil
}

// buildMSearchRequest creates an SSDP M-SEARCH request.
func (s *Scanner) buildMSearchRequest() string {
	return fmt.Sprintf(
		"M-SEARCH * HTTP/1.1\r\n"+
			"HOST: %s\r\n"+
			"MAN: \"ssdp:discover\"\r\n"+
			"MX: %d\r\n"+
			"ST: %s\r\n"+
			"\r\n",
		SSDPMulticastAddr,
		s.config.MX,
		s.config.SearchTarget,
	)
}

// parseResponse parses an SSDP response.
func parseResponse(data []byte) (Device, error) {
	var device Device
	device.Headers = make(map[string]string)

	// Parse as HTTP response
	reader := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		// Try parsing as raw headers
		return parseRawHeaders(data)
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		if len(values) > 0 {
			device.Headers[key] = values[0]
		}
	}

	device.Location = resp.Header.Get("Location")
	device.Server = resp.Header.Get("Server")
	device.USN = resp.Header.Get("USN")
	device.ST = resp.Header.Get("ST")

	return device, nil
}

// parseRawHeaders parses headers when http.ReadResponse fails.
func parseRawHeaders(data []byte) (Device, error) {
	var device Device
	device.Headers = make(map[string]string)

	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines[1:] { // Skip status line
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			device.Headers[key] = value

			switch strings.ToLower(key) {
			case "location":
				device.Location = value
			case "server":
				device.Server = value
			case "usn":
				device.USN = value
			case "st":
				device.ST = value
			}
		}
	}

	return device, nil
}

// DiscoverAll performs discovery on all available interfaces.
func (s *Scanner) DiscoverAll() ([]Device, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var allDevices []Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		wg.Add(1)
		go func(iface net.Interface) {
			defer wg.Done()

			devices, _ := s.discoverOnInterface(iface.Name)
			mu.Lock()
			allDevices = append(allDevices, devices...)
			mu.Unlock()
		}(iface)
	}

	wg.Wait()

	// Deduplicate
	return deduplicateDevices(allDevices), nil
}

// discoverOnInterface performs discovery on a specific interface.
func (s *Scanner) discoverOnInterface(name string) ([]Device, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil {
			continue
		}

		localAddr := &net.UDPAddr{IP: ipNet.IP}
		conn, err := net.ListenUDP("udp4", localAddr)
		if err != nil {
			continue
		}
		defer conn.Close()

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(s.config.Timeout))

		// Create and send M-SEARCH
		request := s.buildMSearchRequest()
		mcastAddr, _ := net.ResolveUDPAddr("udp4", SSDPMulticastAddr)
		conn.WriteToUDP([]byte(request), mcastAddr)

		// Collect responses
		var devices []Device
		buf := make([]byte, 4096)
		startTime := time.Now()

		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}

			device, err := parseResponse(buf[:n])
			if err != nil {
				continue
			}

			device.IP = remoteAddr.IP.String()
			device.ResponseTime = time.Since(startTime)
			devices = append(devices, device)
		}

		return devices, nil
	}

	return nil, nil
}

// deduplicateDevices removes duplicate devices.
func deduplicateDevices(devices []Device) []Device {
	seen := make(map[string]bool)
	var result []Device

	for _, d := range devices {
		key := d.USN
		if key == "" {
			key = d.Location
		}
		if key != "" && !seen[key] {
			seen[key] = true
			result = append(result, d)
		}
	}

	return result
}

// SortByIP sorts devices by IP address.
func SortByIP(devices []Device) {
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].IP < devices[j].IP
	})
}

// SortByResponseTime sorts devices by response time.
func SortByResponseTime(devices []Device) {
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].ResponseTime < devices[j].ResponseTime
	})
}

// FormatDevice formats a device for display.
func FormatDevice(d Device) string {
	deviceType := d.ST
	if deviceType == "" {
		deviceType = "unknown"
	}

	name := d.Server
	if name == "" {
		name = "Unknown Device"
	}

	return fmt.Sprintf("%-15s  %-40s  %s  (%.2fms)",
		d.IP, truncate(name, 40), deviceType, float64(d.ResponseTime.Microseconds())/1000)
}

// truncate truncates a string to a maximum length.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// DeviceType returns a friendly device type name.
func DeviceType(st string) string {
	switch {
	case strings.Contains(st, "rootdevice"):
		return "UPnP Root Device"
	case strings.Contains(st, "InternetGatewayDevice"):
		return "Internet Gateway"
	case strings.Contains(st, "MediaServer"):
		return "Media Server"
	case strings.Contains(st, "MediaRenderer"):
		return "Media Renderer"
	case strings.Contains(st, "Printer"):
		return "Printer"
	case strings.Contains(st, "ssdp:all"):
		return "All Devices"
	default:
		return st
	}
}

// CommonSearchTargets returns common SSDP search targets.
func CommonSearchTargets() []string {
	return []string{
		"ssdp:all",
		"upnp:rootdevice",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:device:MediaServer:1",
		"urn:schemas-upnp-org:device:MediaRenderer:1",
		"urn:schemas-upnp-org:service:ContentDirectory:1",
	}
}
