// Package services provides service/banner detection for network ports.
package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ServiceInfo holds detected service information for a port.
type ServiceInfo struct {
	Port       int
	State      string // "open", "closed", "filtered"
	Protocol   string // "tcp", "udp"
	Service    string // Detected service name
	Version    string // Detected version if available
	Banner     string // Raw banner text
	TLS        bool   // Whether TLS/SSL was detected
	TLSVersion string // TLS version if applicable
	Error      error  // Any error encountered
}

// Scanner performs service detection.
type Scanner struct {
	Host         string
	Ports        []int
	Timeout      time.Duration
	TryTLS       bool // Try TLS connection if plain fails
	SendProbes   bool // Send protocol-specific probes
	MaxBannerLen int  // Maximum banner length to capture
	Concurrency  int  // Number of parallel scans
}

// NewScanner creates a scanner with default settings.
func NewScanner(host string, ports []int) *Scanner {
	return &Scanner{
		Host:         host,
		Ports:        ports,
		Timeout:      5 * time.Second,
		TryTLS:       true,
		SendProbes:   true,
		MaxBannerLen: 1024,
		Concurrency:  10,
	}
}

// ScanAll scans all configured ports and returns results.
func (s *Scanner) ScanAll(ctx context.Context) []ServiceInfo {
	results := make([]ServiceInfo, 0, len(s.Ports))

	// Use a semaphore to limit concurrency
	sem := make(chan struct{}, s.Concurrency)
	resultCh := make(chan ServiceInfo, len(s.Ports))

	portsStarted := 0
PortLoop:
	for _, port := range s.Ports {
		select {
		case <-ctx.Done():
			break PortLoop
		case sem <- struct{}{}:
			portsStarted++
			go func(p int) {
				defer func() { <-sem }()
				resultCh <- s.ScanPort(ctx, p)
			}(port)
		}
	}

	// Wait for all started scans to complete
CollectLoop:
	for i := 0; i < portsStarted; i++ {
		select {
		case <-ctx.Done():
			break CollectLoop
		case result := <-resultCh:
			results = append(results, result)
		}
	}

	return results
}

// ScanPort performs service detection on a single port.
func (s *Scanner) ScanPort(ctx context.Context, port int) ServiceInfo {
	info := ServiceInfo{
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
	}

	address := fmt.Sprintf("%s:%d", s.Host, port)

	// Try plain TCP first
	conn, err := s.dialWithContext(ctx, "tcp", address)
	if err != nil {
		if isTimeout(err) {
			info.State = "filtered"
		}
		info.Error = err
		return info
	}
	defer conn.Close()

	info.State = "open"

	// Try to grab banner
	banner, err := s.grabBanner(conn, port)
	if err == nil && banner != "" {
		info.Banner = banner
		info.Service, info.Version = identifyService(port, banner)
		return info
	}

	// If no banner on plain connection and TLS is enabled, try TLS
	if s.TryTLS && info.Banner == "" {
		tlsInfo := s.tryTLSConnection(ctx, address, port)
		if tlsInfo.Banner != "" || tlsInfo.TLS {
			tlsInfo.State = "open"
			return tlsInfo
		}
	}

	// Fall back to well-known port identification
	if info.Service == "" {
		info.Service = getWellKnownService(port)
	}

	return info
}

// dialWithContext creates a connection with context timeout.
func (s *Scanner) dialWithContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.Timeout}
	return dialer.DialContext(ctx, network, address)
}

// grabBanner attempts to read a banner from the connection.
func (s *Scanner) grabBanner(conn net.Conn, port int) (string, error) {
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Some services need a probe to respond
	if s.SendProbes {
		probe := getProbe(port)
		if probe != "" {
			conn.Write([]byte(probe))
		}
	}

	// Read response
	reader := bufio.NewReader(conn)
	banner := make([]byte, s.MaxBannerLen)
	n, err := reader.Read(banner)
	if err != nil && n == 0 {
		return "", err
	}

	return sanitizeBanner(string(banner[:n])), nil
}

// tryTLSConnection attempts a TLS connection to detect HTTPS/SSL services.
func (s *Scanner) tryTLSConnection(ctx context.Context, address string, port int) ServiceInfo {
	info := ServiceInfo{
		Port:     port,
		Protocol: "tcp",
	}

	dialer := &net.Dialer{Timeout: s.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		info.Error = err
		return info
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.Host,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(s.Timeout))

	err = tlsConn.Handshake()
	if err != nil {
		info.Error = err
		return info
	}

	info.TLS = true
	state := tlsConn.ConnectionState()
	info.TLSVersion = tlsVersionString(state.Version)

	// Try to grab banner over TLS
	banner, _ := s.grabBanner(tlsConn, port)
	info.Banner = banner

	// Identify service
	info.Service, info.Version = identifyService(port, banner)
	if info.Service == "" {
		info.Service = getTLSService(port)
	}

	return info
}

// getProbe returns a protocol-specific probe for the given port.
func getProbe(port int) string {
	probes := map[int]string{
		21:    "USER anonymous\r\n",
		22:    "", // SSH sends banner automatically
		25:    "EHLO probe\r\n",
		80:    "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
		110:   "QUIT\r\n",
		143:   "A001 CAPABILITY\r\n",
		443:   "", // HTTPS - handled by TLS
		465:   "", // SMTPS
		587:   "EHLO probe\r\n",
		993:   "", // IMAPS
		995:   "", // POP3S
		3306:  "", // MySQL sends banner
		5432:  "", // PostgreSQL
		6379:  "PING\r\n",
		27017: "", // MongoDB
	}
	return probes[port]
}

// identifyService attempts to identify the service from its banner.
func identifyService(port int, banner string) (service, version string) {
	bannerLower := strings.ToLower(banner)

	// SSH
	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, "-", 4)
		if len(parts) >= 3 {
			return "ssh", parts[2]
		}
		return "ssh", ""
	}

	// HTTP
	if strings.HasPrefix(banner, "HTTP/") {
		version := extractHTTPServer(banner)
		return "http", version
	}

	// FTP
	if strings.HasPrefix(banner, "220") && strings.Contains(bannerLower, "ftp") {
		return "ftp", extractVersion(banner, `(?i)(\d+\.\d+[\.\d]*)`)[0]
	}

	// SMTP
	if strings.HasPrefix(banner, "220") && strings.Contains(bannerLower, "smtp") {
		return "smtp", ""
	}

	// MySQL
	if strings.Contains(banner, "mysql") || (len(banner) > 4 && banner[4] == 0x0a) {
		return "mysql", extractVersion(banner, `(\d+\.\d+\.\d+)`)[0]
	}

	// Redis
	if strings.HasPrefix(banner, "+PONG") || strings.HasPrefix(banner, "-NOAUTH") {
		return "redis", ""
	}

	// PostgreSQL
	if strings.Contains(bannerLower, "postgresql") {
		return "postgresql", ""
	}

	// MongoDB
	if strings.Contains(banner, "MongoDB") || port == 27017 {
		return "mongodb", ""
	}

	return "", ""
}

// extractHTTPServer extracts server info from HTTP response.
func extractHTTPServer(banner string) string {
	lines := strings.Split(banner, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		}
	}
	return ""
}

// extractVersion extracts version using regex.
func extractVersion(text string, pattern string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(text)
	if len(matches) > 0 {
		return matches
	}
	return []string{""}
}

// getWellKnownService returns the common service for a port.
func getWellKnownService(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		465:   "smtps",
		587:   "submission",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5672:  "amqp",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}
	return services[port]
}

// getTLSService returns common TLS service names.
func getTLSService(port int) string {
	services := map[int]string{
		443:  "https",
		465:  "smtps",
		636:  "ldaps",
		993:  "imaps",
		995:  "pop3s",
		8443: "https-alt",
	}
	if svc, ok := services[port]; ok {
		return svc
	}
	return "ssl/tls"
}

// sanitizeBanner cleans up banner text for display.
func sanitizeBanner(banner string) string {
	// Replace non-printable characters
	var result strings.Builder
	for _, r := range banner {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		} else {
			result.WriteRune('.')
		}
	}

	// Trim and limit length
	s := strings.TrimSpace(result.String())
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// tlsVersionString converts TLS version to string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// isTimeout checks if an error is a timeout.
func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// CommonPorts returns a list of commonly scanned ports.
func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
		465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5672,
		6379, 8080, 8443, 27017,
	}
}

// TopPorts returns the top N most common ports.
func TopPorts(n int) []int {
	all := CommonPorts()
	if n >= len(all) {
		return all
	}
	return all[:n]
}
