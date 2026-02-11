// Package netaudit provides network security auditing by checking for common misconfigurations.
package netaudit

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// CheckType identifies the type of security check.
type CheckType string

const (
	CheckOpenDNS      CheckType = "open-dns"
	CheckSNMPDefault  CheckType = "snmp-default"
	CheckSSH          CheckType = "ssh"
	CheckTelnet       CheckType = "telnet"
	CheckExposedHTTP  CheckType = "exposed-http"
	CheckWeakTLS      CheckType = "weak-tls"
	CheckOpenPorts    CheckType = "open-ports"
	CheckBannerLeak   CheckType = "banner-leak"
	CheckOpenRelay    CheckType = "open-relay"
	CheckDefaultCreds CheckType = "default-creds"
)

// Finding represents a single security finding.
type Finding struct {
	Check       CheckType
	Severity    Severity
	Title       string
	Description string
	Detail      string
	Host        string
	Port        int
	Remediation string
}

// AuditResult holds the complete audit results for a host.
type AuditResult struct {
	Target    string
	Findings  []Finding
	ChecksRun int
	StartTime time.Time
	Duration  time.Duration
	Summary   AuditSummary
}

// AuditSummary contains aggregate counts.
type AuditSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
	Score    int // 0-100 security score
	Grade    string
}

// Options configures the audit.
type Options struct {
	Target       string
	Timeout      time.Duration
	Concurrency  int
	CheckDNS     bool
	CheckSNMP    bool
	CheckSSH     bool
	CheckTelnet  bool
	CheckHTTP    bool
	CheckTLS     bool
	CheckPorts   bool
	CheckBanners bool
	CustomPorts  []int
}

// DefaultOptions returns sensible defaults with all checks enabled.
func DefaultOptions() Options {
	return Options{
		Timeout:      5 * time.Second,
		Concurrency:  10,
		CheckDNS:     true,
		CheckSNMP:    true,
		CheckSSH:     true,
		CheckTelnet:  true,
		CheckHTTP:    true,
		CheckTLS:     true,
		CheckPorts:   true,
		CheckBanners: true,
		CustomPorts: []int{
			21, 22, 23, 25, 53, 80, 110, 143, 161, 443,
			445, 993, 995, 1433, 1883, 3306, 3389, 5432,
			5900, 6379, 8080, 8443, 9200, 27017,
		},
	}
}

// Auditor performs network security audits.
type Auditor struct {
	opts     Options
	resolver *net.Resolver
}

// NewAuditor creates a new auditor.
func NewAuditor(opts Options) *Auditor {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if len(opts.CustomPorts) == 0 {
		opts.CustomPorts = DefaultOptions().CustomPorts
	}
	return &Auditor{
		opts:     opts,
		resolver: net.DefaultResolver,
	}
}

// Audit performs the security audit against the target.
func (a *Auditor) Audit(ctx context.Context) (*AuditResult, error) {
	start := time.Now()
	result := &AuditResult{
		Target:    a.opts.Target,
		StartTime: start,
	}

	// Resolve target to IP
	ips, err := a.resolver.LookupIPAddr(ctx, a.opts.Target)
	if err != nil && net.ParseIP(a.opts.Target) == nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", a.opts.Target, err)
	}

	targetIP := a.opts.Target
	if len(ips) > 0 {
		targetIP = ips[0].IP.String()
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.opts.Concurrency)

	addFindings := func(findings []Finding) {
		mu.Lock()
		result.Findings = append(result.Findings, findings...)
		mu.Unlock()
	}

	incChecks := func() {
		mu.Lock()
		result.ChecksRun++
		mu.Unlock()
	}

	// Port scan first
	if a.opts.CheckPorts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			incChecks()
			findings := a.checkOpenPorts(ctx, targetIP)
			addFindings(findings)
		}()
	}

	// DNS resolver check
	if a.opts.CheckDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			incChecks()
			findings := a.checkOpenDNS(ctx, targetIP)
			addFindings(findings)
		}()
	}

	// SNMP check
	if a.opts.CheckSNMP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			incChecks()
			findings := a.checkSNMP(ctx, targetIP)
			addFindings(findings)
		}()
	}

	// SSH check
	if a.opts.CheckSSH {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			incChecks()
			findings := a.checkSSH(ctx, targetIP)
			addFindings(findings)
		}()
	}

	// Telnet check
	if a.opts.CheckTelnet {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			incChecks()
			findings := a.checkTelnet(ctx, targetIP)
			addFindings(findings)
		}()
	}

	// HTTP check
	if a.opts.CheckHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			incChecks()
			findings := a.checkHTTP(ctx, targetIP)
			addFindings(findings)
		}()
	}

	// TLS check
	if a.opts.CheckTLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			incChecks()
			findings := a.checkTLSSecurity(ctx, targetIP)
			addFindings(findings)
		}()
	}

	// Banner grabbing
	if a.opts.CheckBanners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			incChecks()
			findings := a.checkBannerLeak(ctx, targetIP)
			addFindings(findings)
		}()
	}

	wg.Wait()

	// Sort findings by severity
	sort.Slice(result.Findings, func(i, j int) bool {
		return severityOrder(result.Findings[i].Severity) < severityOrder(result.Findings[j].Severity)
	})

	result.Summary = calculateSummary(result.Findings)
	result.Duration = time.Since(start)

	return result, nil
}

func severityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	default:
		return 5
	}
}

func calculateSummary(findings []Finding) AuditSummary {
	s := AuditSummary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}

	// Score: start at 100, deduct by severity
	s.Score = 100 - (s.Critical * 25) - (s.High * 15) - (s.Medium * 8) - (s.Low * 3)
	if s.Score < 0 {
		s.Score = 0
	}

	switch {
	case s.Score >= 90 && s.Critical == 0:
		s.Grade = "A"
	case s.Score >= 80 && s.Critical == 0:
		s.Grade = "B"
	case s.Score >= 60:
		s.Grade = "C"
	case s.Score >= 40:
		s.Grade = "D"
	default:
		s.Grade = "F"
	}

	return s
}

// --- Individual checks ---

func (a *Auditor) checkOpenPorts(ctx context.Context, ip string) []Finding {
	var findings []Finding
	var openPorts []int

	for _, port := range a.opts.CustomPorts {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, a.opts.Timeout)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}

	dangerousPorts := map[int]string{
		21:    "FTP",
		23:    "Telnet",
		25:    "SMTP",
		110:   "POP3",
		143:   "IMAP",
		445:   "SMB",
		1433:  "MSSQL",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		9200:  "Elasticsearch",
		27017: "MongoDB",
	}

	for _, port := range openPorts {
		if name, dangerous := dangerousPorts[port]; dangerous {
			sev := SeverityHigh
			if port == 23 || port == 6379 || port == 27017 {
				sev = SeverityCritical
			}
			findings = append(findings, Finding{
				Check:       CheckOpenPorts,
				Severity:    sev,
				Title:       fmt.Sprintf("Exposed %s service", name),
				Description: fmt.Sprintf("Port %d (%s) is open and accessible", port, name),
				Host:        ip,
				Port:        port,
				Remediation: fmt.Sprintf("Restrict access to port %d using firewall rules", port),
			})
		}
	}

	if len(openPorts) > 10 {
		findings = append(findings, Finding{
			Check:       CheckOpenPorts,
			Severity:    SeverityMedium,
			Title:       "Many open ports detected",
			Description: fmt.Sprintf("%d ports are open, increasing attack surface", len(openPorts)),
			Detail:      fmt.Sprintf("Open ports: %v", openPorts),
			Host:        ip,
			Remediation: "Close unnecessary ports and services",
		})
	}

	return findings
}

func (a *Auditor) checkOpenDNS(ctx context.Context, ip string) []Finding {
	var findings []Finding

	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:53", ip), a.opts.Timeout)
	if err != nil {
		return findings
	}
	defer conn.Close()

	// Build a simple DNS query for google.com
	query := buildDNSQuery("google.com")
	conn.SetWriteDeadline(time.Now().Add(a.opts.Timeout))
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(a.opts.Timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)

	if err == nil && n > 0 && n >= 12 {
		// Got a DNS response — this is an open resolver
		flags := uint16(buf[2])<<8 | uint16(buf[3])
		isResponse := flags&0x8000 != 0
		rcode := flags & 0x0F
		if isResponse && rcode == 0 {
			findings = append(findings, Finding{
				Check:       CheckOpenDNS,
				Severity:    SeverityHigh,
				Title:       "Open DNS resolver detected",
				Description: "Host responds to DNS queries from external sources",
				Detail:      "Open DNS resolvers can be abused for DDoS amplification attacks",
				Host:        ip,
				Port:        53,
				Remediation: "Restrict DNS queries to authorized networks only",
			})
		}
	}

	return findings
}

func (a *Auditor) checkSNMP(ctx context.Context, ip string) []Finding {
	var findings []Finding

	communities := []string{"public", "private", "community"}

	for _, community := range communities {
		conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:161", ip), a.opts.Timeout)
		if err != nil {
			return findings
		}

		// Build SNMP v2c GET request for sysDescr.0
		snmpReq := buildSNMPGetRequest(community)
		conn.SetWriteDeadline(time.Now().Add(a.opts.Timeout))
		conn.Write(snmpReq)

		conn.SetReadDeadline(time.Now().Add(a.opts.Timeout))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && n > 0 {
			sev := SeverityHigh
			if community == "public" || community == "private" {
				sev = SeverityCritical
			}
			findings = append(findings, Finding{
				Check:       CheckSNMPDefault,
				Severity:    sev,
				Title:       "SNMP accessible with default community string",
				Description: fmt.Sprintf("SNMP responds to community string '%s'", community),
				Detail:      "Default SNMP community strings expose device configuration",
				Host:        ip,
				Port:        161,
				Remediation: "Change default SNMP community strings or disable SNMPv2",
			})
			break
		}
	}

	return findings
}

func (a *Auditor) checkSSH(ctx context.Context, ip string) []Finding {
	var findings []Finding

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), a.opts.Timeout)
	if err != nil {
		return findings
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(a.opts.Timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return findings
	}

	banner := strings.TrimSpace(string(buf[:n]))

	// Check for SSH version info leakage
	findings = append(findings, Finding{
		Check:       CheckSSH,
		Severity:    SeverityInfo,
		Title:       "SSH service detected",
		Description: "SSH is running and accessible",
		Detail:      fmt.Sprintf("Banner: %s", banner),
		Host:        ip,
		Port:        22,
	})

	if strings.Contains(strings.ToLower(banner), "ssh-1") {
		findings = append(findings, Finding{
			Check:       CheckSSH,
			Severity:    SeverityCritical,
			Title:       "SSHv1 protocol detected",
			Description: "SSHv1 has known cryptographic weaknesses",
			Detail:      banner,
			Host:        ip,
			Port:        22,
			Remediation: "Disable SSHv1 and use SSHv2 only",
		})
	}

	// Check for old versions
	lowerBanner := strings.ToLower(banner)
	if strings.Contains(lowerBanner, "openssh_6") || strings.Contains(lowerBanner, "openssh_5") ||
		strings.Contains(lowerBanner, "openssh_4") {
		findings = append(findings, Finding{
			Check:       CheckSSH,
			Severity:    SeverityHigh,
			Title:       "Outdated SSH server version",
			Description: "Running an old OpenSSH version with known vulnerabilities",
			Detail:      banner,
			Host:        ip,
			Port:        22,
			Remediation: "Update OpenSSH to the latest stable version",
		})
	}

	return findings
}

func (a *Auditor) checkTelnet(ctx context.Context, ip string) []Finding {
	var findings []Finding

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:23", ip), a.opts.Timeout)
	if err != nil {
		return findings
	}
	conn.Close()

	findings = append(findings, Finding{
		Check:       CheckTelnet,
		Severity:    SeverityCritical,
		Title:       "Telnet service exposed",
		Description: "Telnet transmits credentials in plaintext",
		Host:        ip,
		Port:        23,
		Remediation: "Disable Telnet and use SSH instead",
	})

	return findings
}

func (a *Auditor) checkHTTP(ctx context.Context, ip string) []Finding {
	var findings []Finding

	for _, port := range []int{80, 8080} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), a.opts.Timeout)
		if err != nil {
			continue
		}

		// Send a HEAD request
		req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
		conn.SetWriteDeadline(time.Now().Add(a.opts.Timeout))
		conn.Write([]byte(req))

		conn.SetReadDeadline(time.Now().Add(a.opts.Timeout))
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		conn.Close()

		if err != nil || n == 0 {
			continue
		}

		response := string(buf[:n])
		lowerResp := strings.ToLower(response)

		// Check for server header revealing details
		if strings.Contains(lowerResp, "server:") {
			for _, line := range strings.Split(response, "\r\n") {
				if strings.HasPrefix(strings.ToLower(line), "server:") {
					serverVal := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					if containsVersion(serverVal) {
						findings = append(findings, Finding{
							Check:       CheckExposedHTTP,
							Severity:    SeverityLow,
							Title:       "HTTP server version disclosure",
							Description: "Server header reveals software version",
							Detail:      fmt.Sprintf("Server: %s", serverVal),
							Host:        ip,
							Port:        port,
							Remediation: "Configure server to hide version information",
						})
					}
					break
				}
			}
		}

		// Check for missing security headers
		if !strings.Contains(lowerResp, "x-frame-options") &&
			!strings.Contains(lowerResp, "x-content-type-options") {
			findings = append(findings, Finding{
				Check:       CheckExposedHTTP,
				Severity:    SeverityLow,
				Title:       "Missing HTTP security headers",
				Description: "Common security headers (X-Frame-Options, X-Content-Type-Options) not set",
				Host:        ip,
				Port:        port,
				Remediation: "Add security headers to HTTP responses",
			})
		}
	}

	return findings
}

func (a *Auditor) checkTLSSecurity(ctx context.Context, ip string) []Finding {
	var findings []Finding

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", ip), a.opts.Timeout)
	if err != nil {
		return findings
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         a.opts.Target,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(a.opts.Timeout))
	err = tlsConn.Handshake()
	if err != nil {
		conn.Close()
		return findings
	}

	state := tlsConn.ConnectionState()
	tlsConn.Close()

	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, Finding{
			Check:       CheckWeakTLS,
			Severity:    SeverityHigh,
			Title:       "Weak TLS version",
			Description: fmt.Sprintf("Server supports %s which has known vulnerabilities", tlsVersionName(state.Version)),
			Host:        ip,
			Port:        443,
			Remediation: "Configure server to use TLS 1.2 or higher only",
		})
	}

	// Check certificate expiry
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)

		if daysUntilExpiry < 0 {
			findings = append(findings, Finding{
				Check:       CheckWeakTLS,
				Severity:    SeverityCritical,
				Title:       "Expired TLS certificate",
				Description: fmt.Sprintf("Certificate expired %d days ago", -daysUntilExpiry),
				Host:        ip,
				Port:        443,
				Remediation: "Renew the TLS certificate immediately",
			})
		} else if daysUntilExpiry < 30 {
			findings = append(findings, Finding{
				Check:       CheckWeakTLS,
				Severity:    SeverityMedium,
				Title:       "TLS certificate expiring soon",
				Description: fmt.Sprintf("Certificate expires in %d days", daysUntilExpiry),
				Host:        ip,
				Port:        443,
				Remediation: "Renew the TLS certificate before expiry",
			})
		}
	}

	return findings
}

func (a *Auditor) checkBannerLeak(ctx context.Context, ip string) []Finding {
	var findings []Finding
	bannerPorts := []struct {
		port int
		name string
	}{
		{21, "FTP"},
		{25, "SMTP"},
		{110, "POP3"},
		{143, "IMAP"},
	}

	for _, bp := range bannerPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, bp.port), a.opts.Timeout)
		if err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(a.opts.Timeout))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		conn.Close()

		if err != nil || n == 0 {
			continue
		}

		banner := strings.TrimSpace(string(buf[:n]))
		if containsVersion(banner) {
			findings = append(findings, Finding{
				Check:       CheckBannerLeak,
				Severity:    SeverityLow,
				Title:       fmt.Sprintf("%s banner leaks version information", bp.name),
				Description: "Service banner reveals software and version details",
				Detail:      fmt.Sprintf("Banner: %s", truncate(banner, 80)),
				Host:        ip,
				Port:        bp.port,
				Remediation: fmt.Sprintf("Configure %s to hide version in banner", bp.name),
			})
		}
	}

	return findings
}

// --- Helpers ---

func buildDNSQuery(domain string) []byte {
	// Simplified DNS query packet
	query := []byte{
		0xAA, 0xBB, // Transaction ID
		0x01, 0x00, // Flags: standard query, recursion desired
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
	}

	// Encode domain name
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00) // Root label

	// Type A (1), Class IN (1)
	query = append(query, 0x00, 0x01, 0x00, 0x01)

	return query
}

func buildSNMPGetRequest(community string) []byte {
	// SNMPv2c GET-REQUEST for sysDescr.0 (1.3.6.1.2.1.1.1.0)
	oid := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

	// Build inner varbinds
	varbind := []byte{0x30} // SEQUENCE
	varbindContent := append([]byte{0x06, byte(len(oid))}, oid...)
	varbindContent = append(varbindContent, 0x05, 0x00) // NULL value
	varbind = append(varbind, byte(len(varbindContent)))
	varbind = append(varbind, varbindContent...)

	varbindList := []byte{0x30, byte(len(varbind))}
	varbindList = append(varbindList, varbind...)

	// PDU
	pdu := []byte{0xa0} // GET-REQUEST
	pduContent := []byte{
		0x02, 0x01, 0x01, // request-id: 1
		0x02, 0x01, 0x00, // error-status: 0
		0x02, 0x01, 0x00, // error-index: 0
	}
	pduContent = append(pduContent, varbindList...)
	pdu = append(pdu, byte(len(pduContent)))
	pdu = append(pdu, pduContent...)

	// Message
	msg := []byte{0x30}                                         // SEQUENCE
	msgContent := []byte{0x02, 0x01, 0x01}                      // version: SNMPv2c
	msgContent = append(msgContent, 0x04, byte(len(community))) // OCTET STRING
	msgContent = append(msgContent, []byte(community)...)
	msgContent = append(msgContent, pdu...)
	msg = append(msg, byte(len(msgContent)))
	msg = append(msg, msgContent...)

	return msg
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

func containsVersion(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' && strings.ContainsAny(s, "./") {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Format returns formatted audit results.
func (r *AuditResult) Format() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\nNetwork Security Audit: %s\n", r.Target))
	sb.WriteString(strings.Repeat("═", 60) + "\n\n")

	// Grade
	gradeIcon := "✓"
	switch r.Summary.Grade {
	case "C":
		gradeIcon = "△"
	case "D":
		gradeIcon = "!"
	case "F":
		gradeIcon = "✗"
	}
	sb.WriteString(fmt.Sprintf("Grade:    %s %s\n", gradeIcon, r.Summary.Grade))
	sb.WriteString(fmt.Sprintf("Score:    %d/100\n", r.Summary.Score))
	sb.WriteString(fmt.Sprintf("Checks:   %d run\n", r.ChecksRun))
	sb.WriteString(fmt.Sprintf("Findings: %d total\n\n", r.Summary.Total))

	if r.Summary.Critical > 0 {
		sb.WriteString(fmt.Sprintf("  🔴 Critical: %d\n", r.Summary.Critical))
	}
	if r.Summary.High > 0 {
		sb.WriteString(fmt.Sprintf("  🟠 High:     %d\n", r.Summary.High))
	}
	if r.Summary.Medium > 0 {
		sb.WriteString(fmt.Sprintf("  🟡 Medium:   %d\n", r.Summary.Medium))
	}
	if r.Summary.Low > 0 {
		sb.WriteString(fmt.Sprintf("  🟢 Low:      %d\n", r.Summary.Low))
	}
	if r.Summary.Info > 0 {
		sb.WriteString(fmt.Sprintf("  ℹ  Info:     %d\n", r.Summary.Info))
	}

	// Detailed findings
	if len(r.Findings) > 0 {
		sb.WriteString("\nFindings:\n")
		sb.WriteString(strings.Repeat("─", 60) + "\n")

		for i, f := range r.Findings {
			icon := severityIcon(f.Severity)
			sb.WriteString(fmt.Sprintf("\n%d. %s [%s] %s\n", i+1, icon, f.Severity, f.Title))
			sb.WriteString(fmt.Sprintf("   %s\n", f.Description))
			if f.Detail != "" {
				sb.WriteString(fmt.Sprintf("   Detail: %s\n", f.Detail))
			}
			if f.Port > 0 {
				sb.WriteString(fmt.Sprintf("   Host: %s:%d\n", f.Host, f.Port))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("   Fix: %s\n", f.Remediation))
			}
		}
	} else {
		sb.WriteString("\n✓ No security issues detected\n")
	}

	sb.WriteString(fmt.Sprintf("\nCompleted in %v\n", r.Duration.Round(time.Millisecond)))

	return sb.String()
}

// FormatCompact returns a single-line summary.
func (r *AuditResult) FormatCompact() string {
	return fmt.Sprintf("Grade %s (%d/100) - %s: C:%d H:%d M:%d L:%d I:%d",
		r.Summary.Grade, r.Summary.Score, r.Target,
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🟢"
	case SeverityInfo:
		return "ℹ"
	default:
		return "?"
	}
}
