// Package snmp provides SNMP device discovery and OID walking capabilities.
package snmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Version represents SNMP protocol version.
type Version int

const (
	Version1  Version = 0
	Version2c Version = 1
	Version3  Version = 3
)

func (v Version) String() string {
	switch v {
	case Version1:
		return "SNMPv1"
	case Version2c:
		return "SNMPv2c"
	case Version3:
		return "SNMPv3"
	default:
		return "Unknown"
	}
}

// CommonCommunities are default community strings to test.
var CommonCommunities = []string{
	"public",
	"private",
	"community",
	"snmp",
	"admin",
	"default",
	"monitor",
	"manager",
}

// CommonOIDs are well-known OIDs for system information.
var CommonOIDs = map[string]string{
	"1.3.6.1.2.1.1.1.0": "sysDescr",
	"1.3.6.1.2.1.1.2.0": "sysObjectID",
	"1.3.6.1.2.1.1.3.0": "sysUpTime",
	"1.3.6.1.2.1.1.4.0": "sysContact",
	"1.3.6.1.2.1.1.5.0": "sysName",
	"1.3.6.1.2.1.1.6.0": "sysLocation",
	"1.3.6.1.2.1.1.7.0": "sysServices",
}

// Device represents a discovered SNMP device.
type Device struct {
	IP              string
	Port            int
	Community       string
	Version         Version
	SysDescr        string
	SysName         string
	SysLocation     string
	SysContact      string
	SysUpTime       time.Duration
	SysObjectID     string
	ResponseTime    time.Duration
	OIDValues       map[string]string
	OpenCommunities []string
	SecurityRisk    string
}

// OIDResult represents an OID query result.
type OIDResult struct {
	OID   string
	Name  string
	Value string
	Type  string
}

// ScanResult contains SNMP scan results.
type ScanResult struct {
	Target      string
	Devices     []Device
	Scanned     int
	Found       int
	StartTime   time.Time
	Duration    time.Duration
	Errors      []string
	Communities []string
}

// Config holds SNMP scanner configuration.
type Config struct {
	Port          int
	Communities   []string
	Timeout       time.Duration
	Retries       int
	Version       Version
	Concurrency   int
	WalkOIDs      bool
	SecurityAudit bool
	CustomOIDs    []string
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Port:          161,
		Communities:   []string{"public"},
		Timeout:       3 * time.Second,
		Retries:       1,
		Version:       Version2c,
		Concurrency:   10,
		WalkOIDs:      true,
		SecurityAudit: true,
	}
}

// Scanner performs SNMP scanning.
type Scanner struct {
	config Config
}

// New creates a new SNMP scanner.
func New(cfg Config) *Scanner {
	if cfg.Port <= 0 {
		cfg.Port = 161
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if len(cfg.Communities) == 0 {
		cfg.Communities = []string{"public"}
	}
	return &Scanner{config: cfg}
}

// ScanHost scans a single host for SNMP.
func (s *Scanner) ScanHost(ctx context.Context, host string) (*Device, error) {
	addr := fmt.Sprintf("%s:%d", host, s.config.Port)

	for _, community := range s.config.Communities {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		device, err := s.probe(ctx, addr, community)
		if err == nil && device != nil {
			// Found responsive device
			if s.config.SecurityAudit {
				device.OpenCommunities = s.auditCommunities(ctx, addr)
				device.SecurityRisk = assessRisk(device.OpenCommunities)
			}
			return device, nil
		}
	}

	return nil, fmt.Errorf("no SNMP response from %s", host)
}

// ScanNetwork scans a network range for SNMP devices.
func (s *Scanner) ScanNetwork(ctx context.Context, cidr string) (*ScanResult, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("invalid CIDR or IP: %s", cidr)
		}
		device, err := s.ScanHost(ctx, cidr)
		result := &ScanResult{
			Target:      cidr,
			Scanned:     1,
			StartTime:   time.Now(),
			Communities: s.config.Communities,
		}
		if err == nil && device != nil {
			result.Devices = []Device{*device}
			result.Found = 1
		}
		result.Duration = time.Since(result.StartTime)
		return result, nil
	}

	result := &ScanResult{
		Target:      cidr,
		StartTime:   time.Now(),
		Communities: s.config.Communities,
	}

	hosts := generateHosts(ipNet)
	result.Scanned = len(hosts)

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.config.Concurrency)

	for _, host := range hosts {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(result.StartTime)
			return result, ctx.Err()
		case semaphore <- struct{}{}:
		}

		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			device, err := s.ScanHost(ctx, h)
			if err == nil && device != nil {
				mu.Lock()
				result.Devices = append(result.Devices, *device)
				result.Found++
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	result.Duration = time.Since(result.StartTime)

	// Sort by IP
	sort.Slice(result.Devices, func(i, j int) bool {
		return result.Devices[i].IP < result.Devices[j].IP
	})

	return result, nil
}

// WalkOID performs SNMP walk on an OID subtree.
func (s *Scanner) WalkOID(ctx context.Context, host, community, baseOID string) ([]OIDResult, error) {
	var results []OIDResult

	// For simplicity, we'll Get common OIDs under the base
	for oid, name := range CommonOIDs {
		if strings.HasPrefix(oid, baseOID) || baseOID == "" || baseOID == "1.3.6.1.2.1.1" {
			value, err := s.getOID(ctx, host, community, oid)
			if err == nil && value != "" {
				results = append(results, OIDResult{
					OID:   oid,
					Name:  name,
					Value: value,
					Type:  "STRING",
				})
			}
		}
	}

	return results, nil
}

// GetOID retrieves a single OID value.
func (s *Scanner) GetOID(ctx context.Context, host, community, oid string) (string, error) {
	return s.getOID(ctx, host, community, oid)
}

func (s *Scanner) probe(ctx context.Context, addr, community string) (*Device, error) {
	conn, err := net.DialTimeout("udp", addr, s.config.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Set deadline
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(s.config.Timeout)
	}
	conn.SetDeadline(deadline)

	// Build SNMPv2c GetRequest for sysDescr
	packet := buildGetRequest(community, "1.3.6.1.2.1.1.1.0")

	start := time.Now()
	_, err = conn.Write(packet)
	if err != nil {
		return nil, err
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	responseTime := time.Since(start)

	// Parse response
	device := &Device{
		IP:           strings.Split(addr, ":")[0],
		Port:         s.config.Port,
		Community:    community,
		Version:      s.config.Version,
		ResponseTime: responseTime,
		OIDValues:    make(map[string]string),
	}

	// Extract value from response
	value := parseResponse(buf[:n])
	device.SysDescr = value
	device.OIDValues["1.3.6.1.2.1.1.1.0"] = value

	// Get additional OIDs if walk is enabled
	if s.config.WalkOIDs {
		s.populateDeviceInfo(ctx, device, community)
	}

	return device, nil
}

func (s *Scanner) populateDeviceInfo(ctx context.Context, device *Device, community string) {
	addr := fmt.Sprintf("%s:%d", device.IP, device.Port)

	// Get sysName
	if val, err := s.getOIDDirect(ctx, addr, community, "1.3.6.1.2.1.1.5.0"); err == nil {
		device.SysName = val
		device.OIDValues["1.3.6.1.2.1.1.5.0"] = val
	}

	// Get sysLocation
	if val, err := s.getOIDDirect(ctx, addr, community, "1.3.6.1.2.1.1.6.0"); err == nil {
		device.SysLocation = val
		device.OIDValues["1.3.6.1.2.1.1.6.0"] = val
	}

	// Get sysContact
	if val, err := s.getOIDDirect(ctx, addr, community, "1.3.6.1.2.1.1.4.0"); err == nil {
		device.SysContact = val
		device.OIDValues["1.3.6.1.2.1.1.4.0"] = val
	}

	// Get sysObjectID
	if val, err := s.getOIDDirect(ctx, addr, community, "1.3.6.1.2.1.1.2.0"); err == nil {
		device.SysObjectID = val
		device.OIDValues["1.3.6.1.2.1.1.2.0"] = val
	}
}

func (s *Scanner) getOID(ctx context.Context, host, community, oid string) (string, error) {
	addr := fmt.Sprintf("%s:%d", host, s.config.Port)
	return s.getOIDDirect(ctx, addr, community, oid)
}

func (s *Scanner) getOIDDirect(ctx context.Context, addr, community, oid string) (string, error) {
	conn, err := net.DialTimeout("udp", addr, s.config.Timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(s.config.Timeout)
	}
	conn.SetDeadline(deadline)

	packet := buildGetRequest(community, oid)
	_, err = conn.Write(packet)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	return parseResponse(buf[:n]), nil
}

func (s *Scanner) auditCommunities(ctx context.Context, addr string) []string {
	var open []string

	for _, community := range CommonCommunities {
		conn, err := net.DialTimeout("udp", addr, s.config.Timeout)
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(s.config.Timeout))
		packet := buildGetRequest(community, "1.3.6.1.2.1.1.1.0")
		conn.Write(packet)

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && n > 0 {
			// Check if response is valid (not an error)
			if !isErrorResponse(buf[:n]) {
				open = append(open, community)
			}
		}
	}

	return open
}

func assessRisk(communities []string) string {
	if len(communities) == 0 {
		return "Low"
	}

	hasDefault := false
	hasPrivate := false

	for _, c := range communities {
		switch c {
		case "public", "private", "community":
			hasDefault = true
		case "admin", "manager":
			hasPrivate = true
		}
	}

	if hasPrivate {
		return "Critical - Admin/Manager community exposed"
	}
	if hasDefault && len(communities) > 1 {
		return "High - Multiple default communities"
	}
	if hasDefault {
		return "Medium - Default community string"
	}
	if len(communities) > 2 {
		return "Medium - Multiple communities accessible"
	}
	return "Low"
}

// buildGetRequest creates a minimal SNMPv2c GetRequest packet.
func buildGetRequest(community, oid string) []byte {
	// Parse OID string to numbers
	oidParts := parseOIDString(oid)
	oidBytes := encodeOID(oidParts)

	// Build variable binding
	varBind := append([]byte{0x30}, byte(len(oidBytes)+4))
	varBind = append(varBind, 0x06, byte(len(oidBytes)))
	varBind = append(varBind, oidBytes...)
	varBind = append(varBind, 0x05, 0x00) // NULL value

	// Variable bindings sequence
	varBindList := append([]byte{0x30}, byte(len(varBind)))
	varBindList = append(varBindList, varBind...)

	// PDU (GetRequest = 0xA0)
	requestID := []byte{0x02, 0x01, 0x01}   // INTEGER 1
	errorStatus := []byte{0x02, 0x01, 0x00} // INTEGER 0
	errorIndex := []byte{0x02, 0x01, 0x00}  // INTEGER 0

	pduContent := append(requestID, errorStatus...)
	pduContent = append(pduContent, errorIndex...)
	pduContent = append(pduContent, varBindList...)

	pdu := append([]byte{0xA0}, byte(len(pduContent)))
	pdu = append(pdu, pduContent...)

	// Community string
	commBytes := []byte(community)
	commField := append([]byte{0x04, byte(len(commBytes))}, commBytes...)

	// Version (SNMPv2c = 1)
	versionField := []byte{0x02, 0x01, 0x01}

	// Message
	msgContent := append(versionField, commField...)
	msgContent = append(msgContent, pdu...)

	// SEQUENCE wrapper
	msg := append([]byte{0x30}, byte(len(msgContent)))
	msg = append(msg, msgContent...)

	return msg
}

func parseOIDString(oid string) []int {
	parts := strings.Split(oid, ".")
	result := make([]int, len(parts))
	for i, p := range parts {
		fmt.Sscanf(p, "%d", &result[i])
	}
	return result
}

func encodeOID(parts []int) []byte {
	if len(parts) < 2 {
		return nil
	}

	var result []byte
	// First two parts encoded as (first * 40 + second)
	result = append(result, byte(parts[0]*40+parts[1]))

	for _, p := range parts[2:] {
		if p < 128 {
			result = append(result, byte(p))
		} else {
			// Multi-byte encoding
			var bytes []byte
			for p > 0 {
				bytes = append([]byte{byte(p & 0x7F)}, bytes...)
				p >>= 7
			}
			for i := 0; i < len(bytes)-1; i++ {
				bytes[i] |= 0x80
			}
			result = append(result, bytes...)
		}
	}

	return result
}

func parseResponse(data []byte) string {
	// Simple parser - look for octet string value
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x04 { // OCTET STRING
			length := int(data[i+1])
			if length > 0 && i+2+length <= len(data) {
				return string(data[i+2 : i+2+length])
			}
		}
	}
	return ""
}

func isErrorResponse(data []byte) bool {
	// Check for error-status in response
	// This is a simplified check
	return len(data) < 10
}

func generateHosts(ipNet *net.IPNet) []string {
	var hosts []string

	ip := ipNet.IP.Mask(ipNet.Mask)
	ones, bits := ipNet.Mask.Size()

	if bits-ones > 16 {
		// Too large, limit to /16
		return hosts
	}

	numHosts := 1 << (bits - ones)
	if numHosts > 65536 {
		numHosts = 65536
	}

	ipInt := binary.BigEndian.Uint32(ip.To4())

	for i := 1; i < numHosts-1; i++ {
		newIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(newIP, ipInt+uint32(i))
		hosts = append(hosts, newIP.String())
	}

	return hosts
}

// Format returns formatted scan results.
func (r *ScanResult) Format() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("SNMP Scan Results: %s\n", r.Target))
	sb.WriteString(strings.Repeat("─", 70) + "\n\n")

	if len(r.Devices) == 0 {
		sb.WriteString("No SNMP devices found.\n")
	} else {
		for _, d := range r.Devices {
			sb.WriteString(fmt.Sprintf("📡 %s (Community: %s)\n", d.IP, d.Community))
			if d.SysName != "" {
				sb.WriteString(fmt.Sprintf("   Name:     %s\n", d.SysName))
			}
			if d.SysDescr != "" {
				descr := d.SysDescr
				if len(descr) > 60 {
					descr = descr[:57] + "..."
				}
				sb.WriteString(fmt.Sprintf("   Descr:    %s\n", descr))
			}
			if d.SysLocation != "" {
				sb.WriteString(fmt.Sprintf("   Location: %s\n", d.SysLocation))
			}
			sb.WriteString(fmt.Sprintf("   Response: %v\n", d.ResponseTime.Round(time.Millisecond)))

			if len(d.OpenCommunities) > 0 {
				sb.WriteString(fmt.Sprintf("   ⚠️  Open Communities: %s\n", strings.Join(d.OpenCommunities, ", ")))
				sb.WriteString(fmt.Sprintf("   🔒 Risk: %s\n", d.SecurityRisk))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString(strings.Repeat("─", 70) + "\n")
	sb.WriteString(fmt.Sprintf("Scanned: %d hosts | Found: %d devices | Duration: %v\n",
		r.Scanned, r.Found, r.Duration.Round(time.Millisecond)))

	return sb.String()
}
