// Package netstat provides network connection and routing information.
package netstat

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Connection represents a network connection.
type Connection struct {
	Protocol   string // tcp, udp, tcp6, udp6
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	State      string // ESTABLISHED, LISTEN, TIME_WAIT, etc.
	PID        int
	Process    string
}

// RoutingEntry represents a routing table entry.
type RoutingEntry struct {
	Destination string
	Gateway     string
	Mask        string
	Interface   string
	Metric      int
	Flags       string
}

// Interface represents a network interface.
type Interface struct {
	Name       string
	IP         string
	MAC        string
	MTU        int
	BytesRecv  uint64
	BytesSent  uint64
	PacketRecv uint64
	PacketSent uint64
}

// GetConnections retrieves active network connections.
func GetConnections(showPID bool) ([]Connection, error) {
	switch runtime.GOOS {
	case "windows":
		return getConnectionsWindows(showPID)
	case "linux":
		return getConnectionsLinux(showPID)
	case "darwin":
		return getConnectionsDarwin(showPID)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// GetRoutingTable retrieves the system routing table.
func GetRoutingTable() ([]RoutingEntry, error) {
	switch runtime.GOOS {
	case "windows":
		return getRoutingWindows()
	case "linux":
		return getRoutingLinux()
	case "darwin":
		return getRoutingDarwin()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getConnectionsWindows retrieves connections on Windows.
func getConnectionsWindows(showPID bool) ([]Connection, error) {
	args := []string{"-ano"}
	cmd := exec.Command("netstat", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}
	return parseWindowsNetstat(string(output))
}

// parseWindowsNetstat parses Windows netstat -ano output.
func parseWindowsNetstat(output string) ([]Connection, error) {
	connections := make([]Connection, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip headers
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Proto") {
			break
		}
	}

	// Parse connection lines
	connRe := regexp.MustCompile(`^\s*(\w+)\s+(\S+)\s+(\S+)\s+(\w+)?\s*(\d+)?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := connRe.FindStringSubmatch(line)
		if len(matches) < 4 {
			continue
		}

		conn := Connection{
			Protocol: strings.ToLower(matches[1]),
		}

		// Parse local address
		localAddr, localPort := parseAddress(matches[2])
		conn.LocalAddr = localAddr
		conn.LocalPort = localPort

		// Parse remote address
		remoteAddr, remotePort := parseAddress(matches[3])
		conn.RemoteAddr = remoteAddr
		conn.RemotePort = remotePort

		// State (TCP only)
		if len(matches) > 4 && matches[4] != "" {
			conn.State = matches[4]
		}

		// PID
		if len(matches) > 5 && matches[5] != "" {
			conn.PID, _ = strconv.Atoi(matches[5])
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// getConnectionsLinux retrieves connections on Linux.
func getConnectionsLinux(showPID bool) ([]Connection, error) {
	args := []string{"-tuln"}
	if showPID {
		args = []string{"-tulnp"}
	}
	cmd := exec.Command("ss", args...)
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		cmd = exec.Command("netstat", args...)
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("ss/netstat failed: %w", err)
		}
	}
	return parseLinuxSS(string(output))
}

// parseLinuxSS parses ss command output.
func parseLinuxSS(output string) ([]Connection, error) {
	connections := make([]Connection, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip header
	if scanner.Scan() {
		// Header skipped
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}

		conn := Connection{
			Protocol: strings.ToLower(fields[0]),
			State:    fields[1],
		}

		// Parse local address
		localAddr, localPort := parseAddress(fields[4])
		conn.LocalAddr = localAddr
		conn.LocalPort = localPort

		// Parse remote address if present
		if len(fields) > 5 {
			remoteAddr, remotePort := parseAddress(fields[5])
			conn.RemoteAddr = remoteAddr
			conn.RemotePort = remotePort
		}

		// Parse PID/Process if present
		if len(fields) > 6 {
			pidMatch := regexp.MustCompile(`pid=(\d+)`).FindStringSubmatch(fields[6])
			if len(pidMatch) > 1 {
				conn.PID, _ = strconv.Atoi(pidMatch[1])
			}
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// getConnectionsDarwin retrieves connections on macOS.
func getConnectionsDarwin(showPID bool) ([]Connection, error) {
	args := []string{"-an"}
	if showPID {
		args = []string{"-anv"}
	}
	cmd := exec.Command("netstat", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}
	return parseDarwinNetstat(string(output))
}

// parseDarwinNetstat parses macOS netstat output.
func parseDarwinNetstat(output string) ([]Connection, error) {
	connections := make([]Connection, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// Skip non-connection lines
		if len(fields) < 5 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}

		conn := Connection{
			Protocol: proto,
		}

		// Parse addresses
		localAddr, localPort := parseAddress(fields[3])
		conn.LocalAddr = localAddr
		conn.LocalPort = localPort

		remoteAddr, remotePort := parseAddress(fields[4])
		conn.RemoteAddr = remoteAddr
		conn.RemotePort = remotePort

		// State
		if len(fields) > 5 {
			conn.State = fields[5]
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

// parseAddress parses an address:port string.
func parseAddress(addr string) (string, int) {
	// Handle IPv6 addresses like [::]:80
	if strings.HasPrefix(addr, "[") {
		idx := strings.LastIndex(addr, "]:")
		if idx != -1 {
			ip := addr[1:idx]
			portStr := addr[idx+2:]
			port, _ := strconv.Atoi(portStr)
			return ip, port
		}
		return addr, 0
	}

	// Handle IPv4 addresses like 192.168.1.1:80
	idx := strings.LastIndex(addr, ":")
	if idx != -1 {
		ip := addr[:idx]
		portStr := addr[idx+1:]
		port, _ := strconv.Atoi(portStr)
		// Handle * as wildcard
		if ip == "*" || ip == "0.0.0.0" {
			ip = "0.0.0.0"
		}
		return ip, port
	}

	return addr, 0
}

// getRoutingWindows retrieves routing table on Windows.
func getRoutingWindows() ([]RoutingEntry, error) {
	cmd := exec.Command("route", "print")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("route print failed: %w", err)
	}
	return parseWindowsRoute(string(output))
}

// parseWindowsRoute parses Windows route print output.
func parseWindowsRoute(output string) ([]RoutingEntry, error) {
	entries := make([]RoutingEntry, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	inIPv4Section := false
	routeRe := regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "IPv4 Route Table") {
			inIPv4Section = true
			continue
		}
		if strings.Contains(line, "IPv6 Route Table") {
			inIPv4Section = false
			continue
		}

		if !inIPv4Section {
			continue
		}

		matches := routeRe.FindStringSubmatch(line)
		if len(matches) > 5 {
			metric, _ := strconv.Atoi(matches[5])
			entry := RoutingEntry{
				Destination: matches[1],
				Mask:        matches[2],
				Gateway:     matches[3],
				Interface:   matches[4],
				Metric:      metric,
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// getRoutingLinux retrieves routing table on Linux.
func getRoutingLinux() ([]RoutingEntry, error) {
	cmd := exec.Command("ip", "route")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to route command
		cmd = exec.Command("route", "-n")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("ip route failed: %w", err)
		}
		return parseLinuxRoute(string(output))
	}
	return parseLinuxIPRoute(string(output))
}

// parseLinuxIPRoute parses ip route command output.
func parseLinuxIPRoute(output string) ([]RoutingEntry, error) {
	entries := make([]RoutingEntry, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		entry := RoutingEntry{
			Destination: fields[0],
		}

		for i := 0; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				entry.Gateway = fields[i+1]
			case "dev":
				entry.Interface = fields[i+1]
			case "metric":
				entry.Metric, _ = strconv.Atoi(fields[i+1])
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// parseLinuxRoute parses route -n command output.
func parseLinuxRoute(output string) ([]RoutingEntry, error) {
	entries := make([]RoutingEntry, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip headers
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "Destination") {
			break
		}
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		metric, _ := strconv.Atoi(fields[4])
		entry := RoutingEntry{
			Destination: fields[0],
			Gateway:     fields[1],
			Mask:        fields[2],
			Flags:       fields[3],
			Metric:      metric,
			Interface:   fields[7],
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// getRoutingDarwin retrieves routing table on macOS.
func getRoutingDarwin() ([]RoutingEntry, error) {
	cmd := exec.Command("netstat", "-rn")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat -rn failed: %w", err)
	}
	return parseDarwinRoute(string(output))
}

// parseDarwinRoute parses macOS netstat -rn output.
func parseDarwinRoute(output string) ([]RoutingEntry, error) {
	entries := make([]RoutingEntry, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))

	inIPv4Section := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Internet:") {
			inIPv4Section = true
			continue
		}
		if strings.Contains(line, "Internet6:") {
			inIPv4Section = false
			continue
		}

		if !inIPv4Section || strings.HasPrefix(line, "Destination") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		entry := RoutingEntry{
			Destination: fields[0],
			Gateway:     fields[1],
			Flags:       fields[2],
			Interface:   fields[len(fields)-1],
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// FilterByProtocol filters connections by protocol.
func FilterByProtocol(conns []Connection, protocol string) []Connection {
	filtered := make([]Connection, 0)
	protocol = strings.ToLower(protocol)
	for _, c := range conns {
		if strings.HasPrefix(c.Protocol, protocol) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// FilterByState filters connections by state.
func FilterByState(conns []Connection, state string) []Connection {
	filtered := make([]Connection, 0)
	state = strings.ToUpper(state)
	for _, c := range conns {
		if strings.ToUpper(c.State) == state {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// GetListening returns only listening connections.
func GetListening(conns []Connection) []Connection {
	return FilterByState(conns, "LISTEN")
}

// GetEstablished returns only established connections.
func GetEstablished(conns []Connection) []Connection {
	return FilterByState(conns, "ESTABLISHED")
}
