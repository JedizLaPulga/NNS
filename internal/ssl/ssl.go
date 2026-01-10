// Package ssl provides comprehensive SSL/TLS certificate analysis.
package ssl

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertInfo holds certificate details.
type CertInfo struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	SANs          []string  `json:"sans"`
	SignatureAlg  string    `json:"signature_algorithm"`
	PublicKeyAlg  string    `json:"public_key_algorithm"`
	PublicKeySize int       `json:"public_key_size"`
	IsCA          bool      `json:"is_ca"`
	Fingerprint   string    `json:"fingerprint_sha256"`
	Version       int       `json:"version"`
}

// ChainInfo holds certificate chain details.
type ChainInfo struct {
	Certificates   []CertInfo `json:"certificates"`
	Length         int        `json:"length"`
	IsComplete     bool       `json:"is_complete"`
	HasTrustedRoot bool       `json:"has_trusted_root"`
}

// SecurityIssue represents a security problem found.
type SecurityIssue struct {
	Severity string `json:"severity"` // critical, warning, info
	Message  string `json:"message"`
}

// SecurityInfo holds security analysis results.
type SecurityInfo struct {
	Grade         string          `json:"grade"`
	Score         int             `json:"score"` // 0-100
	Issues        []SecurityIssue `json:"issues"`
	TLSVersion    string          `json:"tls_version"`
	CipherSuite   string          `json:"cipher_suite"`
	IsSelfSigned  bool            `json:"is_self_signed"`
	IsExpired     bool            `json:"is_expired"`
	IsNotYetValid bool            `json:"is_not_yet_valid"`
	HasWeakSig    bool            `json:"has_weak_signature"`
	HasShortKey   bool            `json:"has_short_key"`
}

// Result holds the complete SSL analysis result.
type Result struct {
	Host        string        `json:"host"`
	Port        int           `json:"port"`
	Certificate CertInfo      `json:"certificate"`
	Chain       ChainInfo     `json:"chain"`
	Security    SecurityInfo  `json:"security"`
	ConnectTime time.Duration `json:"connect_time"`
	Error       error         `json:"-"`
	ErrorMsg    string        `json:"error,omitempty"`
}

// Analyzer performs SSL/TLS analysis.
type Analyzer struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// NewAnalyzer creates a new Analyzer with defaults.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Timeout:            10 * time.Second,
		InsecureSkipVerify: true, // We want to analyze even bad certs
	}
}

// Analyze performs full SSL/TLS analysis on a host.
func (a *Analyzer) Analyze(host string, port int) *Result {
	result := &Result{
		Host: host,
		Port: port,
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: a.InsecureSkipVerify,
		ServerName:         host,
	}

	// Connect with timeout
	start := time.Now()
	dialer := &net.Dialer{Timeout: a.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		result.Error = err
		result.ErrorMsg = err.Error()
		return result
	}
	defer conn.Close()

	result.ConnectTime = time.Since(start)

	// Get connection state
	state := conn.ConnectionState()

	// TLS version
	result.Security.TLSVersion = tlsVersionString(state.Version)
	result.Security.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Analyze certificates
	if len(state.PeerCertificates) == 0 {
		result.Error = fmt.Errorf("no certificates received")
		result.ErrorMsg = "no certificates received"
		return result
	}

	// Leaf certificate
	leaf := state.PeerCertificates[0]
	result.Certificate = parseCertInfo(leaf)

	// Chain
	result.Chain = analyzeChain(state.PeerCertificates, state.VerifiedChains)

	// Security analysis
	result.Security = analyzeSecurityWithBase(result.Security, leaf, state)

	return result
}

// parseCertInfo extracts certificate information.
func parseCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DaysRemaining: int(time.Until(cert.NotAfter).Hours() / 24),
		SANs:          cert.DNSNames,
		SignatureAlg:  cert.SignatureAlgorithm.String(),
		PublicKeyAlg:  cert.PublicKeyAlgorithm.String(),
		IsCA:          cert.IsCA,
		Version:       cert.Version,
	}

	// Fingerprint
	fp := sha256.Sum256(cert.Raw)
	info.Fingerprint = hex.EncodeToString(fp[:])

	// Public key size
	info.PublicKeySize = getPublicKeySize(cert)

	// Add IP SANs
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}

	return info
}

// getPublicKeySize returns the key size in bits.
func getPublicKeySize(cert *x509.Certificate) int {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if cert.PublicKey != nil {
			// RSA key size is in the modulus
			return cert.PublicKey.(interface{ Size() int }).Size() * 8
		}
	case x509.ECDSA:
		// ECDSA sizes by curve
		if cert.PublicKey != nil {
			params := cert.PublicKey.(interface{ Params() interface{} }).Params()
			if p, ok := params.(interface{ BitSize() int }); ok {
				return p.BitSize()
			}
		}
		return 256 // Default assumption
	case x509.Ed25519:
		return 256
	}
	return 0
}

// analyzeChain analyzes the certificate chain.
func analyzeChain(certs []*x509.Certificate, verifiedChains [][]*x509.Certificate) ChainInfo {
	chain := ChainInfo{
		Length:       len(certs),
		Certificates: make([]CertInfo, len(certs)),
	}

	for i, cert := range certs {
		chain.Certificates[i] = parseCertInfo(cert)
	}

	// Check if chain is complete (ends with a CA)
	if len(certs) > 0 {
		lastCert := certs[len(certs)-1]
		chain.IsComplete = lastCert.IsCA
	}

	// Check if we have verified chains (means trusted root)
	chain.HasTrustedRoot = len(verifiedChains) > 0

	return chain
}

// analyzeSecurityWithBase performs security analysis.
func analyzeSecurityWithBase(base SecurityInfo, cert *x509.Certificate, state tls.ConnectionState) SecurityInfo {
	sec := base
	sec.Issues = make([]SecurityIssue, 0)
	sec.Score = 100

	now := time.Now()

	// Check expiry
	if now.After(cert.NotAfter) {
		sec.IsExpired = true
		sec.Issues = append(sec.Issues, SecurityIssue{
			Severity: "critical",
			Message:  fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
		})
		sec.Score -= 40
	} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
		sec.Issues = append(sec.Issues, SecurityIssue{
			Severity: "warning",
			Message:  fmt.Sprintf("Certificate expires in %d days", int(time.Until(cert.NotAfter).Hours()/24)),
		})
		sec.Score -= 10
	}

	// Check not yet valid
	if now.Before(cert.NotBefore) {
		sec.IsNotYetValid = true
		sec.Issues = append(sec.Issues, SecurityIssue{
			Severity: "critical",
			Message:  fmt.Sprintf("Certificate not valid until %s", cert.NotBefore.Format("2006-01-02")),
		})
		sec.Score -= 40
	}

	// Check self-signed
	if cert.Subject.String() == cert.Issuer.String() {
		sec.IsSelfSigned = true
		sec.Issues = append(sec.Issues, SecurityIssue{
			Severity: "warning",
			Message:  "Certificate is self-signed",
		})
		sec.Score -= 20
	}

	// Check signature algorithm
	weakSigs := map[x509.SignatureAlgorithm]bool{
		x509.MD2WithRSA:  true,
		x509.MD5WithRSA:  true,
		x509.SHA1WithRSA: true,
	}
	if weakSigs[cert.SignatureAlgorithm] {
		sec.HasWeakSig = true
		sec.Issues = append(sec.Issues, SecurityIssue{
			Severity: "critical",
			Message:  fmt.Sprintf("Weak signature algorithm: %s", cert.SignatureAlgorithm),
		})
		sec.Score -= 30
	}

	// Check key size
	keySize := getPublicKeySize(cert)
	if cert.PublicKeyAlgorithm == x509.RSA && keySize < 2048 {
		sec.HasShortKey = true
		sec.Issues = append(sec.Issues, SecurityIssue{
			Severity: "critical",
			Message:  fmt.Sprintf("Weak RSA key size: %d bits (minimum 2048)", keySize),
		})
		sec.Score -= 30
	}
	if cert.PublicKeyAlgorithm == x509.ECDSA && keySize < 256 {
		sec.HasShortKey = true
		sec.Issues = append(sec.Issues, SecurityIssue{
			Severity: "critical",
			Message:  fmt.Sprintf("Weak ECDSA key size: %d bits", keySize),
		})
		sec.Score -= 30
	}

	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		sec.Issues = append(sec.Issues, SecurityIssue{
			Severity: "warning",
			Message:  fmt.Sprintf("Outdated TLS version: %s (recommend TLS 1.2+)", sec.TLSVersion),
		})
		sec.Score -= 15
	}

	// Check for weak cipher suites
	weakCiphers := []string{"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}
	for _, weak := range weakCiphers {
		if strings.Contains(sec.CipherSuite, weak) {
			sec.Issues = append(sec.Issues, SecurityIssue{
				Severity: "critical",
				Message:  fmt.Sprintf("Weak cipher suite: %s", sec.CipherSuite),
			})
			sec.Score -= 25
			break
		}
	}

	// Calculate grade
	if sec.Score < 0 {
		sec.Score = 0
	}
	sec.Grade = scoreToGrade(sec.Score)

	return sec
}

// scoreToGrade converts a score to a letter grade.
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
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// ToJSON converts result to JSON.
func (r *Result) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ExpiryStatus returns a human readable expiry status.
func (r *Result) ExpiryStatus() string {
	days := r.Certificate.DaysRemaining
	switch {
	case r.Security.IsExpired:
		return fmt.Sprintf("EXPIRED (%d days ago)", -days)
	case days < 0:
		return fmt.Sprintf("EXPIRED (%d days ago)", -days)
	case days == 0:
		return "EXPIRES TODAY"
	case days <= 7:
		return fmt.Sprintf("CRITICAL: %d days", days)
	case days <= 30:
		return fmt.Sprintf("WARNING: %d days", days)
	case days <= 90:
		return fmt.Sprintf("OK: %d days", days)
	default:
		return fmt.Sprintf("GOOD: %d days", days)
	}
}

// ParseHostPort parses host:port string.
func ParseHostPort(input string) (string, int) {
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) == 2 {
			var port int
			fmt.Sscanf(parts[1], "%d", &port)
			if port > 0 {
				return parts[0], port
			}
		}
	}
	return input, 443
}
