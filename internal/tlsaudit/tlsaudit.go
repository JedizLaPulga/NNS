// Package tlsaudit provides deep TLS/SSL security auditing.
package tlsaudit

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// Severity levels for issues.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Icon returns an emoji for the severity.
func (s Severity) Icon() string {
	switch s {
	case Info:
		return "ℹ️"
	case Low:
		return "🔵"
	case Medium:
		return "🟡"
	case High:
		return "🟠"
	case Critical:
		return "🔴"
	default:
		return "❓"
	}
}

// Issue represents a security finding.
type Issue struct {
	Severity    Severity
	Category    string
	Title       string
	Description string
	Remediation string
}

// ProtocolSupport tracks which TLS versions are supported.
type ProtocolSupport struct {
	SSLv3   bool
	TLS10   bool
	TLS11   bool
	TLS12   bool
	TLS13   bool
	Current string // Currently negotiated version
}

// CipherSupport tracks cipher suite information.
type CipherSupport struct {
	Current     string   // Currently negotiated cipher
	Weak        []string // Weak ciphers detected
	Recommended []string // Recommended ciphers available
}

// CertInfo holds certificate details.
type CertInfo struct {
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	SANs          []string
	KeyType       string
	KeySize       int
	SignatureAlg  string
	Fingerprint   string
	IsCA          bool
	IsSelfSigned  bool
	Version       int
}

// VulnerabilityCheck tracks specific vulnerability tests.
type VulnerabilityCheck struct {
	Name        string
	Description string
	Vulnerable  bool
	Tested      bool
}

// Result holds the complete audit results.
type Result struct {
	Host            string
	Port            int
	Connected       bool
	Error           error
	ConnectTime     time.Duration
	Grade           string
	Score           int
	Protocol        ProtocolSupport
	Cipher          CipherSupport
	Certificate     CertInfo
	ChainLength     int
	ChainValid      bool
	Issues          []Issue
	Vulnerabilities []VulnerabilityCheck
}

// Config configures the auditor.
type Config struct {
	Timeout        time.Duration
	CheckProtocols bool // Test all protocol versions
	CheckVulns     bool // Check for known vulnerabilities
	SkipCertVerify bool // Continue even with cert errors
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:        10 * time.Second,
		CheckProtocols: true,
		CheckVulns:     true,
		SkipCertVerify: true,
	}
}

// Auditor performs TLS security audits.
type Auditor struct {
	config Config
}

// New creates a new Auditor.
func New(cfg Config) *Auditor {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Auditor{config: cfg}
}

// Audit performs a comprehensive TLS audit on a host.
func (a *Auditor) Audit(host string, port int) *Result {
	result := &Result{
		Host:            host,
		Port:            port,
		Score:           100,
		Issues:          make([]Issue, 0),
		Vulnerabilities: make([]VulnerabilityCheck, 0),
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	// Initial connection with default settings
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: a.config.SkipCertVerify,
	}

	dialer := &net.Dialer{Timeout: a.config.Timeout}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	result.ConnectTime = time.Since(start)

	if err != nil {
		result.Connected = false
		result.Error = err
		result.Grade = "F"
		result.Score = 0
		return result
	}
	defer conn.Close()
	result.Connected = true

	state := conn.ConnectionState()

	// Protocol info
	result.Protocol.Current = tlsVersionString(state.Version)
	result.Protocol.TLS12 = state.Version >= tls.VersionTLS12
	result.Protocol.TLS13 = state.Version >= tls.VersionTLS13

	// Cipher info
	result.Cipher.Current = tls.CipherSuiteName(state.CipherSuite)

	// Certificate analysis
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = parseCertInfo(cert)
		result.ChainLength = len(state.PeerCertificates)
		result.ChainValid = len(state.VerifiedChains) > 0
	}

	// Check protocols if enabled
	if a.config.CheckProtocols {
		a.checkProtocols(host, port, result)
	}

	// Check for vulnerabilities
	if a.config.CheckVulns {
		a.checkVulnerabilities(host, port, result)
	}

	// Analyze and score
	a.analyzeAndScore(result)

	return result
}

// checkProtocols tests which TLS versions are supported.
func (a *Auditor) checkProtocols(host string, port int, result *Result) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: a.config.Timeout / 2}

	protocols := []struct {
		version uint16
		field   *bool
	}{
		{tls.VersionTLS10, &result.Protocol.TLS10},
		{tls.VersionTLS11, &result.Protocol.TLS11},
		{tls.VersionTLS12, &result.Protocol.TLS12},
		{tls.VersionTLS13, &result.Protocol.TLS13},
	}

	for _, p := range protocols {
		cfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         p.version,
			MaxVersion:         p.version,
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
		if err == nil {
			*p.field = true
			conn.Close()
		}
	}
}

// checkVulnerabilities checks for known TLS vulnerabilities.
func (a *Auditor) checkVulnerabilities(host string, port int, result *Result) {
	// Check for weak protocols (BEAST, POODLE vulnerability indicators)
	if result.Protocol.TLS10 {
		result.Vulnerabilities = append(result.Vulnerabilities, VulnerabilityCheck{
			Name:        "BEAST",
			Description: "TLS 1.0 CBC vulnerability",
			Vulnerable:  true,
			Tested:      true,
		})
	}

	if result.Protocol.SSLv3 {
		result.Vulnerabilities = append(result.Vulnerabilities, VulnerabilityCheck{
			Name:        "POODLE",
			Description: "SSLv3 protocol vulnerability",
			Vulnerable:  true,
			Tested:      true,
		})
	}

	// Check cipher suite for known weak ciphers
	weakCiphers := []string{"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}
	for _, weak := range weakCiphers {
		if strings.Contains(strings.ToUpper(result.Cipher.Current), weak) {
			result.Cipher.Weak = append(result.Cipher.Weak, result.Cipher.Current)
			break
		}
	}

	// Sweet32 check (3DES)
	if strings.Contains(result.Cipher.Current, "3DES") {
		result.Vulnerabilities = append(result.Vulnerabilities, VulnerabilityCheck{
			Name:        "Sweet32",
			Description: "64-bit block cipher vulnerability (3DES)",
			Vulnerable:  true,
			Tested:      true,
		})
	}

	// Check for CRIME (compression)
	result.Vulnerabilities = append(result.Vulnerabilities, VulnerabilityCheck{
		Name:        "CRIME",
		Description: "TLS compression vulnerability",
		Vulnerable:  false, // Modern Go doesn't support TLS compression
		Tested:      true,
	})
}

// analyzeAndScore analyzes findings and calculates score.
func (a *Auditor) analyzeAndScore(result *Result) {
	// Protocol issues
	if result.Protocol.SSLv3 {
		result.Issues = append(result.Issues, Issue{
			Severity:    Critical,
			Category:    "Protocol",
			Title:       "SSLv3 Enabled",
			Description: "SSLv3 is obsolete and vulnerable to POODLE attack",
			Remediation: "Disable SSLv3 on the server",
		})
		result.Score -= 30
	}

	if result.Protocol.TLS10 {
		result.Issues = append(result.Issues, Issue{
			Severity:    High,
			Category:    "Protocol",
			Title:       "TLS 1.0 Enabled",
			Description: "TLS 1.0 is deprecated and has known vulnerabilities",
			Remediation: "Disable TLS 1.0, use TLS 1.2 or higher",
		})
		result.Score -= 15
	}

	if result.Protocol.TLS11 {
		result.Issues = append(result.Issues, Issue{
			Severity:    Medium,
			Category:    "Protocol",
			Title:       "TLS 1.1 Enabled",
			Description: "TLS 1.1 is deprecated",
			Remediation: "Disable TLS 1.1, use TLS 1.2 or higher",
		})
		result.Score -= 10
	}

	if !result.Protocol.TLS13 {
		result.Issues = append(result.Issues, Issue{
			Severity:    Low,
			Category:    "Protocol",
			Title:       "TLS 1.3 Not Supported",
			Description: "TLS 1.3 provides improved security and performance",
			Remediation: "Enable TLS 1.3 support",
		})
		result.Score -= 5
	}

	// Certificate issues
	if result.Certificate.IsSelfSigned {
		result.Issues = append(result.Issues, Issue{
			Severity:    Medium,
			Category:    "Certificate",
			Title:       "Self-Signed Certificate",
			Description: "Certificate is not signed by a trusted CA",
			Remediation: "Use a certificate from a trusted CA",
		})
		result.Score -= 15
	}

	if result.Certificate.DaysRemaining < 0 {
		result.Issues = append(result.Issues, Issue{
			Severity:    Critical,
			Category:    "Certificate",
			Title:       "Certificate Expired",
			Description: fmt.Sprintf("Certificate expired %d days ago", -result.Certificate.DaysRemaining),
			Remediation: "Renew the certificate immediately",
		})
		result.Score -= 40
	} else if result.Certificate.DaysRemaining <= 7 {
		result.Issues = append(result.Issues, Issue{
			Severity:    High,
			Category:    "Certificate",
			Title:       "Certificate Expiring Soon",
			Description: fmt.Sprintf("Certificate expires in %d days", result.Certificate.DaysRemaining),
			Remediation: "Renew the certificate immediately",
		})
		result.Score -= 20
	} else if result.Certificate.DaysRemaining <= 30 {
		result.Issues = append(result.Issues, Issue{
			Severity:    Medium,
			Category:    "Certificate",
			Title:       "Certificate Expiring",
			Description: fmt.Sprintf("Certificate expires in %d days", result.Certificate.DaysRemaining),
			Remediation: "Plan certificate renewal",
		})
		result.Score -= 10
	}

	// Key size issues
	if result.Certificate.KeyType == "RSA" && result.Certificate.KeySize < 2048 {
		result.Issues = append(result.Issues, Issue{
			Severity:    Critical,
			Category:    "Certificate",
			Title:       "Weak RSA Key",
			Description: fmt.Sprintf("RSA key is only %d bits (minimum 2048 recommended)", result.Certificate.KeySize),
			Remediation: "Generate a new certificate with at least 2048-bit RSA key",
		})
		result.Score -= 30
	}

	// Cipher issues
	if len(result.Cipher.Weak) > 0 {
		result.Issues = append(result.Issues, Issue{
			Severity:    High,
			Category:    "Cipher",
			Title:       "Weak Cipher Suite",
			Description: fmt.Sprintf("Using weak cipher: %s", strings.Join(result.Cipher.Weak, ", ")),
			Remediation: "Configure server to use only strong cipher suites",
		})
		result.Score -= 20
	}

	// Signature algorithm issues
	weakSigAlgs := []string{"MD5", "SHA1"}
	for _, weak := range weakSigAlgs {
		if strings.Contains(strings.ToUpper(result.Certificate.SignatureAlg), weak) {
			result.Issues = append(result.Issues, Issue{
				Severity:    High,
				Category:    "Certificate",
				Title:       "Weak Signature Algorithm",
				Description: fmt.Sprintf("Certificate uses weak signature: %s", result.Certificate.SignatureAlg),
				Remediation: "Generate certificate with SHA-256 or stronger",
			})
			result.Score -= 20
			break
		}
	}

	// Calculate grade
	if result.Score < 0 {
		result.Score = 0
	}
	result.Grade = scoreToGrade(result.Score)
}

func parseCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DaysRemaining: int(time.Until(cert.NotAfter).Hours() / 24),
		SANs:          cert.DNSNames,
		SignatureAlg:  cert.SignatureAlgorithm.String(),
		IsCA:          cert.IsCA,
		IsSelfSigned:  cert.Subject.String() == cert.Issuer.String(),
		Version:       cert.Version,
	}

	// Key info
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType = "RSA"
		info.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType = "ECDSA"
		info.KeySize = pub.Curve.Params().BitSize
	default:
		info.KeyType = cert.PublicKeyAlgorithm.String()
	}

	// Fingerprint
	fp := sha256.Sum256(cert.Raw)
	info.Fingerprint = hex.EncodeToString(fp[:])

	// IP SANs
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}

	return info
}

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
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func scoreToGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// GradeColor returns ANSI color for grade.
func GradeColor(grade string) string {
	switch grade {
	case "A+", "A":
		return "\033[32m" // Green
	case "B":
		return "\033[33m" // Yellow
	case "C":
		return "\033[33m" // Yellow
	case "D":
		return "\033[31m" // Red
	default:
		return "\033[31m" // Red
	}
}

// Reset returns ANSI reset code.
func Reset() string {
	return "\033[0m"
}

// FormatIssue formats an issue for display.
func FormatIssue(issue Issue) string {
	return fmt.Sprintf("%s [%s] %s: %s",
		issue.Severity.Icon(),
		issue.Severity.String(),
		issue.Title,
		issue.Description,
	)
}

// FormatVuln formats a vulnerability check for display.
func FormatVuln(v VulnerabilityCheck) string {
	status := "✅ Not Vulnerable"
	if v.Vulnerable {
		status = "❌ VULNERABLE"
	}
	if !v.Tested {
		status = "⏭️ Not Tested"
	}
	return fmt.Sprintf("  %-12s %s", v.Name+":", status)
}

// CountBySeverity counts issues by severity level.
func CountBySeverity(issues []Issue) map[Severity]int {
	counts := make(map[Severity]int)
	for _, issue := range issues {
		counts[issue.Severity]++
	}
	return counts
}

// ParseHostPort parses host:port with default port 443.
func ParseHostPort(input string) (string, int) {
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) == 2 {
			var port int
			fmt.Sscanf(parts[1], "%d", &port)
			if port > 0 && port <= 65535 {
				return parts[0], port
			}
		}
	}
	return input, 443
}
