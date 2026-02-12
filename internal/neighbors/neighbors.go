// Package neighbors provides mDNS/DNS-SD based network neighbor discovery.
package neighbors

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	mdnsAddr4  = "224.0.0.251:5353"
	mdnsAddr6  = "[ff02::fb]:5353"
	bufferSize = 65536
)

// ServiceType identifies a well-known DNS-SD service.
type ServiceType struct {
	Name        string
	Type        string
	Description string
}

// CommonServices returns a list of frequently-used DNS-SD service types.
func CommonServices() []ServiceType {
	return []ServiceType{
		{"HTTP", "_http._tcp.local.", "Web servers"},
		{"HTTPS", "_https._tcp.local.", "Secure web servers"},
		{"SSH", "_ssh._tcp.local.", "SSH servers"},
		{"SMB", "_smb._tcp.local.", "Windows file sharing"},
		{"FTP", "_ftp._tcp.local.", "FTP servers"},
		{"Printer", "_ipp._tcp.local.", "IPP printers"},
		{"AirPlay", "_airplay._tcp.local.", "Apple AirPlay"},
		{"AirPrint", "_ipp._tcp.local.", "Apple AirPrint printers"},
		{"Chromecast", "_googlecast._tcp.local.", "Google Chromecast"},
		{"Spotify", "_spotify-connect._tcp.local.", "Spotify Connect"},
		{"HomeKit", "_hap._tcp.local.", "Apple HomeKit"},
		{"MQTT", "_mqtt._tcp.local.", "MQTT brokers"},
		{"DNS-SD", "_services._dns-sd._udp.local.", "Service discovery meta-query"},
	}
}

// Neighbor represents a discovered network device.
type Neighbor struct {
	Hostname  string
	Addresses []string
	Services  []DiscoveredService
	FirstSeen time.Time
	Source    string
}

// DiscoveredService is a service found via DNS-SD.
type DiscoveredService struct {
	InstanceName string
	ServiceType  string
	Port         int
	TXT          map[string]string
	Host         string
	Addresses    []string
}

// Result holds the discovery results.
type Result struct {
	Neighbors  []Neighbor
	Services   []DiscoveredService
	TotalHosts int
	TotalSvcs  int
	Duration   time.Duration
	StartTime  time.Time
	Errors     []string
}

// Format returns formatted discovery results.
func (r *Result) Format() string {
	var b strings.Builder

	b.WriteString("\n╔══════════════════════════════════════════╗\n")
	b.WriteString("║       NETWORK NEIGHBOR DISCOVERY         ║\n")
	b.WriteString("╚══════════════════════════════════════════╝\n\n")

	b.WriteString(fmt.Sprintf("  Duration:  %v\n", r.Duration.Round(time.Millisecond)))
	b.WriteString(fmt.Sprintf("  Hosts:     %d discovered\n", r.TotalHosts))
	b.WriteString(fmt.Sprintf("  Services:  %d found\n\n", r.TotalSvcs))

	if len(r.Neighbors) > 0 {
		b.WriteString("  ┌──────────────────── Neighbors ────────────────────\n")
		for i, n := range r.Neighbors {
			b.WriteString(fmt.Sprintf("  │ %d. %s\n", i+1, n.Hostname))
			if len(n.Addresses) > 0 {
				b.WriteString(fmt.Sprintf("  │    Addresses: %s\n", strings.Join(n.Addresses, ", ")))
			}
			if len(n.Services) > 0 {
				svcNames := make([]string, 0, len(n.Services))
				for _, s := range n.Services {
					svcNames = append(svcNames, s.ServiceType)
				}
				b.WriteString(fmt.Sprintf("  │    Services:  %s\n", strings.Join(svcNames, ", ")))
			}
			b.WriteString(fmt.Sprintf("  │    Source:    %s\n", n.Source))
			if i < len(r.Neighbors)-1 {
				b.WriteString("  │\n")
			}
		}
		b.WriteString("  └──────────────────────────────────────────────────\n\n")
	}

	if len(r.Services) > 0 {
		b.WriteString("  ┌──────────────────── Services ────────────────────\n")
		for i, s := range r.Services {
			b.WriteString(fmt.Sprintf("  │ %d. %s (%s)\n", i+1, s.InstanceName, s.ServiceType))
			b.WriteString(fmt.Sprintf("  │    Host: %s", s.Host))
			if s.Port > 0 {
				b.WriteString(fmt.Sprintf(":%d", s.Port))
			}
			b.WriteString("\n")
			if len(s.Addresses) > 0 {
				b.WriteString(fmt.Sprintf("  │    Addr: %s\n", strings.Join(s.Addresses, ", ")))
			}
			if len(s.TXT) > 0 {
				pairs := make([]string, 0, len(s.TXT))
				for k, v := range s.TXT {
					if v != "" {
						pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
					} else {
						pairs = append(pairs, k)
					}
				}
				sort.Strings(pairs)
				b.WriteString(fmt.Sprintf("  │    TXT:  %s\n", strings.Join(pairs, ", ")))
			}
			if i < len(r.Services)-1 {
				b.WriteString("  │\n")
			}
		}
		b.WriteString("  └─────────────────────────────────────────────────\n")
	}

	if len(r.Errors) > 0 {
		b.WriteString("\n  Errors:\n")
		for _, e := range r.Errors {
			b.WriteString(fmt.Sprintf("    ⚠ %s\n", e))
		}
	}

	return b.String()
}

// FormatCompact returns a single-line summary.
func (r *Result) FormatCompact() string {
	return fmt.Sprintf("%d hosts, %d services discovered [%v]",
		r.TotalHosts, r.TotalSvcs, r.Duration.Round(time.Millisecond))
}

// Options configures the discovery.
type Options struct {
	Timeout      time.Duration
	ServiceTypes []string
	UseIPv6      bool
	Interface    string
	OnDiscover   func(Neighbor)
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	types := make([]string, 0)
	for _, s := range CommonServices() {
		types = append(types, s.Type)
	}
	return Options{
		Timeout:      5 * time.Second,
		ServiceTypes: types,
	}
}

// Scanner performs mDNS/DNS-SD network discovery.
type Scanner struct {
	opts      Options
	mu        sync.Mutex
	neighbors map[string]*Neighbor
	services  []DiscoveredService
}

// NewScanner creates a new scanner.
func NewScanner(opts Options) *Scanner {
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	if len(opts.ServiceTypes) == 0 {
		opts.ServiceTypes = DefaultOptions().ServiceTypes
	}

	return &Scanner{
		opts:      opts,
		neighbors: make(map[string]*Neighbor),
		services:  make([]DiscoveredService, 0),
	}
}

// Discover performs the network scan.
func (s *Scanner) Discover(ctx context.Context) (*Result, error) {
	start := time.Now()
	result := &Result{
		StartTime: start,
		Errors:    make([]string, 0),
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()

	conn, err := s.openMDNSConn()
	if err != nil {
		return nil, fmt.Errorf("failed to open mDNS connection: %w", err)
	}
	defer conn.Close()

	// Send queries for each service type
	for _, svcType := range s.opts.ServiceTypes {
		query := buildMDNSQuery(svcType)
		addr, _ := net.ResolveUDPAddr("udp", mdnsAddr4)
		if _, err := conn.WriteTo(query, addr); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("query %s: %v", svcType, err))
		}
	}

	// Collect responses
	buf := make([]byte, bufferSize)
	for {
		select {
		case <-timeoutCtx.Done():
			goto done
		default:
		}

		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if timeoutCtx.Err() != nil {
					goto done
				}
				continue
			}
			continue
		}

		s.processResponse(buf[:n], remoteAddr)
	}

done:
	// Compile results
	s.mu.Lock()
	for _, n := range s.neighbors {
		result.Neighbors = append(result.Neighbors, *n)
	}
	result.Services = append(result.Services, s.services...)
	s.mu.Unlock()

	sort.Slice(result.Neighbors, func(i, j int) bool {
		return result.Neighbors[i].Hostname < result.Neighbors[j].Hostname
	})

	result.TotalHosts = len(result.Neighbors)
	result.TotalSvcs = len(result.Services)
	result.Duration = time.Since(start)

	return result, nil
}

func (s *Scanner) openMDNSConn() (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp4", mdnsAddr4)
	if err != nil {
		return nil, err
	}

	var iface *net.Interface
	if s.opts.Interface != "" {
		iface, err = net.InterfaceByName(s.opts.Interface)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", s.opts.Interface, err)
		}
	}

	conn, err := net.ListenMulticastUDP("udp4", iface, addr)
	if err != nil {
		// Fallback: try a regular UDP socket
		localAddr, _ := net.ResolveUDPAddr("udp4", ":0")
		conn, err = net.ListenUDP("udp4", localAddr)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

func (s *Scanner) processResponse(data []byte, from net.Addr) {
	msg, err := parseDNSMessage(data)
	if err != nil {
		return
	}

	fromIP := ""
	if addr, ok := from.(*net.UDPAddr); ok {
		fromIP = addr.IP.String()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Extract hostnames and addresses from answers
	for _, rr := range msg.answers {
		switch rr.rrType {
		case dnsTypeA, dnsTypeAAAA:
			hostname := strings.TrimSuffix(rr.name, ".local.")
			hostname = strings.TrimSuffix(hostname, ".")
			if hostname == "" {
				hostname = fromIP
			}

			n, exists := s.neighbors[hostname]
			if !exists {
				n = &Neighbor{
					Hostname:  hostname,
					Addresses: []string{},
					Services:  []DiscoveredService{},
					FirstSeen: time.Now(),
					Source:    "mDNS",
				}
				s.neighbors[hostname] = n
			}

			ip := parseIPFromRData(rr.rdata, rr.rrType)
			if ip != "" && !containsString(n.Addresses, ip) {
				n.Addresses = append(n.Addresses, ip)
			}

		case dnsTypePTR:
			instanceName := string(rr.rdata)
			svc := DiscoveredService{
				InstanceName: cleanDNSName(instanceName),
				ServiceType:  cleanDNSName(rr.name),
			}
			s.services = append(s.services, svc)

		case dnsTypeSRV:
			if len(rr.rdata) >= 6 {
				srvPort := int(rr.rdata[4])<<8 | int(rr.rdata[5])
				srvHost := cleanDNSName(string(rr.rdata[6:]))

				// Update existing service if found
				for i := range s.services {
					if s.services[i].InstanceName == cleanDNSName(rr.name) || s.services[i].ServiceType == cleanDNSName(rr.name) {
						s.services[i].Port = srvPort
						s.services[i].Host = srvHost
					}
				}

				// Also register as neighbor
				hostname := strings.TrimSuffix(srvHost, ".local.")
				hostname = strings.TrimSuffix(hostname, ".")
				if _, exists := s.neighbors[hostname]; !exists {
					s.neighbors[hostname] = &Neighbor{
						Hostname:  hostname,
						Source:    "DNS-SD",
						FirstSeen: time.Now(),
						Addresses: []string{},
						Services:  []DiscoveredService{},
					}
				}
			}

		case dnsTypeTXT:
			txt := parseTXTRecord(rr.rdata)
			name := cleanDNSName(rr.name)
			for i := range s.services {
				if s.services[i].InstanceName == name {
					s.services[i].TXT = txt
				}
			}
		}
	}

	// If we got any answers from this IP, ensure it's registered
	if fromIP != "" && len(msg.answers) > 0 {
		if _, exists := s.neighbors[fromIP]; !exists {
			s.neighbors[fromIP] = &Neighbor{
				Hostname:  fromIP,
				Addresses: []string{fromIP},
				Source:    "mDNS",
				FirstSeen: time.Now(),
				Services:  []DiscoveredService{},
			}
		}
	}
}

// --- DNS message parsing (minimal mDNS support) ---

const (
	dnsTypeA    uint16 = 1
	dnsTypeNS   uint16 = 2
	dnsTypePTR  uint16 = 12
	dnsTypeTXT  uint16 = 16
	dnsTypeAAAA uint16 = 28
	dnsTypeSRV  uint16 = 33
)

type dnsResourceRecord struct {
	name   string
	rrType uint16
	class  uint16
	ttl    uint32
	rdata  []byte
}

type dnsMessage struct {
	id        uint16
	flags     uint16
	questions int
	answers   []dnsResourceRecord
}

func buildMDNSQuery(name string) []byte {
	// Construct a minimal DNS query
	buf := make([]byte, 0, 64)

	// Header: ID=0, Flags=0 (standard query), QDCOUNT=1
	buf = append(buf, 0, 0) // ID
	buf = append(buf, 0, 0) // Flags
	buf = append(buf, 0, 1) // QDCOUNT
	buf = append(buf, 0, 0) // ANCOUNT
	buf = append(buf, 0, 0) // NSCOUNT
	buf = append(buf, 0, 0) // ARCOUNT

	// Question
	buf = append(buf, encodeDNSName(name)...)
	buf = append(buf, 0, 12) // QTYPE = PTR (12)
	buf = append(buf, 0, 1)  // QCLASS = IN

	return buf
}

func encodeDNSName(name string) []byte {
	var buf []byte
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		buf = append(buf, byte(len(p)))
		buf = append(buf, []byte(p)...)
	}
	buf = append(buf, 0)
	return buf
}

func parseDNSMessage(data []byte) (*dnsMessage, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("message too short")
	}

	msg := &dnsMessage{
		id:        uint16(data[0])<<8 | uint16(data[1]),
		flags:     uint16(data[2])<<8 | uint16(data[3]),
		questions: int(uint16(data[4])<<8 | uint16(data[5])),
		answers:   make([]dnsResourceRecord, 0),
	}

	ancount := int(uint16(data[6])<<8 | uint16(data[7]))

	offset := 12

	// Skip questions
	for i := 0; i < msg.questions && offset < len(data); i++ {
		_, newOffset, err := decodeDNSName(data, offset)
		if err != nil {
			return msg, nil
		}
		offset = newOffset + 4 // QTYPE + QCLASS
	}

	// Parse answers
	totalRR := ancount
	// Also parse authority and additional records
	nscount := int(uint16(data[8])<<8 | uint16(data[9]))
	arcount := int(uint16(data[10])<<8 | uint16(data[11]))
	totalRR += nscount + arcount

	for i := 0; i < totalRR && offset < len(data); i++ {
		name, newOffset, err := decodeDNSName(data, offset)
		if err != nil {
			break
		}
		offset = newOffset

		if offset+10 > len(data) {
			break
		}

		rrType := uint16(data[offset])<<8 | uint16(data[offset+1])
		class := uint16(data[offset+2])<<8 | uint16(data[offset+3])
		ttl := uint32(data[offset+4])<<24 | uint32(data[offset+5])<<16 |
			uint32(data[offset+6])<<8 | uint32(data[offset+7])
		rdlen := int(uint16(data[offset+8])<<8 | uint16(data[offset+9]))
		offset += 10

		if offset+rdlen > len(data) {
			break
		}

		rdata := make([]byte, rdlen)
		copy(rdata, data[offset:offset+rdlen])

		// For PTR, SRV, decode the name in rdata
		if rrType == dnsTypePTR {
			ptrName, _, err := decodeDNSName(data, offset)
			if err == nil {
				rdata = []byte(ptrName)
			}
		}

		msg.answers = append(msg.answers, dnsResourceRecord{
			name:   name,
			rrType: rrType,
			class:  class,
			ttl:    ttl,
			rdata:  rdata,
		})

		offset += rdlen
	}

	return msg, nil
}

func decodeDNSName(data []byte, offset int) (string, int, error) {
	var parts []string
	visited := make(map[int]bool)
	startOffset := offset
	jumped := false

	for offset < len(data) {
		if visited[offset] {
			return "", 0, fmt.Errorf("DNS name loop detected")
		}
		visited[offset] = true

		length := int(data[offset])

		if length == 0 {
			if !jumped {
				offset++
			}
			break
		}

		// DNS name compression pointer
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated pointer")
			}
			ptr := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			if !jumped {
				startOffset = offset + 2
			}
			offset = ptr
			jumped = true
			continue
		}

		offset++
		if offset+length > len(data) {
			return "", 0, fmt.Errorf("label exceeds message")
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	name := strings.Join(parts, ".")
	if jumped {
		return name, startOffset, nil
	}
	return name, offset, nil
}

func parseIPFromRData(rdata []byte, rrType uint16) string {
	switch rrType {
	case dnsTypeA:
		if len(rdata) == 4 {
			return net.IP(rdata).String()
		}
	case dnsTypeAAAA:
		if len(rdata) == 16 {
			return net.IP(rdata).String()
		}
	}
	return ""
}

func parseTXTRecord(rdata []byte) map[string]string {
	txt := make(map[string]string)
	offset := 0
	for offset < len(rdata) {
		length := int(rdata[offset])
		offset++
		if offset+length > len(rdata) {
			break
		}
		entry := string(rdata[offset : offset+length])
		offset += length

		if idx := strings.IndexByte(entry, '='); idx >= 0 {
			txt[entry[:idx]] = entry[idx+1:]
		} else {
			txt[entry] = ""
		}
	}
	return txt
}

func cleanDNSName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return name
}

func containsString(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}
