// Package routes provides routing table analysis and gateway detection.
package routes

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Route represents a single routing table entry.
type Route struct {
	Destination    string
	Gateway        string
	Netmask        string
	Flags          string
	Metric         int
	Interface      string
	InterfaceIndex int
	IsDefault      bool
	IsHost         bool   // Host route (single IP)
	Protocol       string // Route protocol (e.g., kernel, static, dhcp)
	Source         string // Preferred source address
}

// RoutingTable represents the complete routing table.
type RoutingTable struct {
	Routes         []Route
	DefaultGateway string
	DefaultIface   string
	IPv4Routes     int
	IPv6Routes     int
	Timestamp      time.Time
}

// GatewayInfo contains information about a gateway.
type GatewayInfo struct {
	IP         string
	Interface  string
	Reachable  bool
	RTT        time.Duration
	MACAddress string
	Hostname   string
	IsDefault  bool
}

// GetRoutes retrieves the system routing table.
func GetRoutes() (*RoutingTable, error) {
	switch runtime.GOOS {
	case "windows":
		return getWindowsRoutes()
	case "linux":
		return getLinuxRoutes()
	case "darwin":
		return getDarwinRoutes()
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// getWindowsRoutes gets routes on Windows using 'route print'.
func getWindowsRoutes() (*RoutingTable, error) {
	table := &RoutingTable{
		Routes:    []Route{},
		Timestamp: time.Now(),
	}

	cmd := exec.Command("route", "print")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute 'route print': %w", err)
	}

	lines := strings.Split(string(output), "\n")
	inIPv4Section := false
	inIPv6Section := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Detect sections
		if strings.Contains(line, "IPv4 Route Table") {
			inIPv4Section = true
			inIPv6Section = false
			continue
		}
		if strings.Contains(line, "IPv6 Route Table") {
			inIPv4Section = false
			inIPv6Section = true
			continue
		}
		if strings.Contains(line, "Persistent Routes") {
			inIPv4Section = false
			inIPv6Section = false
			continue
		}

		if inIPv4Section {
			route := parseWindowsIPv4Route(line)
			if route != nil {
				table.Routes = append(table.Routes, *route)
				table.IPv4Routes++
				if route.IsDefault {
					table.DefaultGateway = route.Gateway
					table.DefaultIface = route.Interface
				}
			}
		} else if inIPv6Section {
			route := parseWindowsIPv6Route(line)
			if route != nil {
				table.Routes = append(table.Routes, *route)
				table.IPv6Routes++
			}
		}
	}

	return table, nil
}

// parseWindowsIPv4Route parses a Windows IPv4 route line.
func parseWindowsIPv4Route(line string) *Route {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}

	// Skip header lines
	if fields[0] == "Network" || fields[0] == "===========" {
		return nil
	}

	// Validate first field is an IP
	if net.ParseIP(fields[0]) == nil && fields[0] != "0.0.0.0" {
		return nil
	}

	route := &Route{
		Destination: fields[0],
		Netmask:     fields[1],
		Gateway:     fields[2],
		Interface:   fields[3],
	}

	if len(fields) >= 5 {
		route.Metric, _ = strconv.Atoi(fields[4])
	}

	route.IsDefault = route.Destination == "0.0.0.0" && route.Netmask == "0.0.0.0"
	route.IsHost = route.Netmask == "255.255.255.255"

	return route
}

// parseWindowsIPv6Route parses a Windows IPv6 route line.
func parseWindowsIPv6Route(line string) *Route {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	// Skip header
	if fields[0] == "If" || strings.HasPrefix(line, "===") {
		return nil
	}

	// Format: If   Metric   Destination   Gateway
	ifIndex, _ := strconv.Atoi(fields[0])
	metric, _ := strconv.Atoi(fields[1])

	route := &Route{
		InterfaceIndex: ifIndex,
		Metric:         metric,
		Destination:    fields[2],
	}

	if len(fields) >= 4 {
		route.Gateway = fields[3]
	}

	route.IsDefault = route.Destination == "::/0"

	return route
}

// getLinuxRoutes gets routes on Linux using 'ip route'.
func getLinuxRoutes() (*RoutingTable, error) {
	table := &RoutingTable{
		Routes:    []Route{},
		Timestamp: time.Now(),
	}

	// Get IPv4 routes
	cmd := exec.Command("ip", "-4", "route", "show")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat -rn
		return getLinuxRoutesFallback()
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		route := parseLinuxRoute(scanner.Text())
		if route != nil {
			table.Routes = append(table.Routes, *route)
			table.IPv4Routes++
			if route.IsDefault {
				table.DefaultGateway = route.Gateway
				table.DefaultIface = route.Interface
			}
		}
	}

	// Get IPv6 routes
	cmd = exec.Command("ip", "-6", "route", "show")
	output, _ = cmd.Output()
	scanner = bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		route := parseLinuxRoute(scanner.Text())
		if route != nil {
			table.Routes = append(table.Routes, *route)
			table.IPv6Routes++
		}
	}

	return table, nil
}

// parseLinuxRoute parses a Linux 'ip route' output line.
func parseLinuxRoute(line string) *Route {
	if line == "" {
		return nil
	}

	route := &Route{}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	// First field is destination or 'default'
	if parts[0] == "default" {
		route.Destination = "0.0.0.0/0"
		route.IsDefault = true
	} else {
		route.Destination = parts[0]
	}

	// Parse remaining key-value pairs
	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "via":
			if i+1 < len(parts) {
				route.Gateway = parts[i+1]
				i++
			}
		case "dev":
			if i+1 < len(parts) {
				route.Interface = parts[i+1]
				i++
			}
		case "metric":
			if i+1 < len(parts) {
				route.Metric, _ = strconv.Atoi(parts[i+1])
				i++
			}
		case "proto":
			if i+1 < len(parts) {
				route.Protocol = parts[i+1]
				i++
			}
		case "src":
			if i+1 < len(parts) {
				route.Source = parts[i+1]
				i++
			}
		}
	}

	return route
}

// getLinuxRoutesFallback uses netstat as fallback.
func getLinuxRoutesFallback() (*RoutingTable, error) {
	table := &RoutingTable{
		Routes:    []Route{},
		Timestamp: time.Now(),
	}

	cmd := exec.Command("netstat", "-rn")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get routes: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// Skip header
		if fields[0] == "Destination" || fields[0] == "Kernel" {
			continue
		}

		route := &Route{
			Destination: fields[0],
			Gateway:     fields[1],
			Netmask:     fields[2],
			Flags:       fields[3],
			Interface:   fields[7],
		}
		route.Metric, _ = strconv.Atoi(fields[4])
		route.IsDefault = fields[0] == "0.0.0.0"

		table.Routes = append(table.Routes, *route)
		table.IPv4Routes++

		if route.IsDefault {
			table.DefaultGateway = route.Gateway
			table.DefaultIface = route.Interface
		}
	}

	return table, nil
}

// getDarwinRoutes gets routes on macOS.
func getDarwinRoutes() (*RoutingTable, error) {
	table := &RoutingTable{
		Routes:    []Route{},
		Timestamp: time.Now(),
	}

	cmd := exec.Command("netstat", "-rn")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute 'netstat -rn': %w", err)
	}

	lines := strings.Split(string(output), "\n")
	inIPv4 := false
	inIPv6 := false

	for _, line := range lines {
		if strings.Contains(line, "Internet:") && !strings.Contains(line, "Internet6:") {
			inIPv4 = true
			inIPv6 = false
			continue
		}
		if strings.Contains(line, "Internet6:") {
			inIPv4 = false
			inIPv6 = true
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "Destination" {
			continue
		}

		route := &Route{
			Destination: fields[0],
			Gateway:     fields[1],
			Flags:       fields[2],
		}
		if len(fields) > 3 {
			route.Interface = fields[len(fields)-1]
		}

		route.IsDefault = fields[0] == "default"

		table.Routes = append(table.Routes, *route)
		if inIPv4 {
			table.IPv4Routes++
		} else if inIPv6 {
			table.IPv6Routes++
		}

		if route.IsDefault && inIPv4 {
			table.DefaultGateway = route.Gateway
			table.DefaultIface = route.Interface
		}
	}

	return table, nil
}

// TestGateway tests connectivity to a gateway.
func TestGateway(gateway string, timeout time.Duration) *GatewayInfo {
	info := &GatewayInfo{
		IP:        gateway,
		Reachable: false,
	}

	// Attempt TCP connection to port 80 (just to test reachability)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", gateway+":80", timeout)
	if err == nil {
		conn.Close()
		info.Reachable = true
		info.RTT = time.Since(start)
	} else {
		// Try ICMP-like test via UDP
		conn, err := net.DialTimeout("udp", gateway+":33434", timeout)
		if err == nil {
			conn.Close()
			info.Reachable = true
			info.RTT = time.Since(start)
		}
	}

	// Try to resolve hostname
	names, _ := net.LookupAddr(gateway)
	if len(names) > 0 {
		info.Hostname = strings.TrimSuffix(names[0], ".")
	}

	return info
}

// GetDefaultGateway quickly retrieves just the default gateway.
func GetDefaultGateway() (string, error) {
	table, err := GetRoutes()
	if err != nil {
		return "", err
	}
	if table.DefaultGateway == "" {
		return "", fmt.Errorf("no default gateway found")
	}
	return table.DefaultGateway, nil
}

// Filter returns routes matching a destination pattern.
func (t *RoutingTable) Filter(pattern string) []Route {
	var filtered []Route
	for _, r := range t.Routes {
		if strings.Contains(r.Destination, pattern) ||
			strings.Contains(r.Gateway, pattern) ||
			strings.Contains(r.Interface, pattern) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// GetInterfaceRoutes returns routes for a specific interface.
func (t *RoutingTable) GetInterfaceRoutes(iface string) []Route {
	var routes []Route
	for _, r := range t.Routes {
		if r.Interface == iface {
			routes = append(routes, r)
		}
	}
	return routes
}

// Summary returns a summary string.
func (t *RoutingTable) Summary() string {
	return fmt.Sprintf("Total routes: %d (IPv4: %d, IPv6: %d), Default gateway: %s via %s",
		len(t.Routes), t.IPv4Routes, t.IPv6Routes, t.DefaultGateway, t.DefaultIface)
}
