// Package tlscheck provides TLS certificate chain validation and analysis.
package tlscheck

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Certificate represents a certificate in the chain.
type Certificate struct {
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	DaysUntilExpiry    int
	SerialNumber       string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	DNSNames           []string
	IPAddresses        []net.IP
	IsCA               bool
	IsSelfSigned       bool
	KeyUsage           []string
	ExtKeyUsage        []string
	OCSPServers        []string
	CRLDistribution    []string
	Fingerprint        string
}

// ChainResult represents the full certificate chain analysis.
type ChainResult struct {
	Host              string
	Port              int
	Verified          bool
	VerifyError       string
	TLSVersion        string
	CipherSuite       string
	ServerName        string
	Certificates      []Certificate
	ChainValid        bool
	ChainError        string
	ConnectTime       time.Duration
	HandshakeTime     time.Duration
	ExpiryWarnings    []string
	SecurityWarnings  []string
	Grade             string
}

// Checker configures TLS certificate checking.
type Checker struct {
	Host          string
	Port          int
	Timeout       time.Duration
	SkipVerify    bool
	ServerName    string
	WarningDays   int // Days before expiry to trigger warning
	CriticalDays  int // Days before expiry to trigger critical
}

// NewChecker creates a new Checker with default settings.
func NewChecker(host string, port int) *Checker {
	return &Checker{
		Host:         host,
		Port:         port,
		Timeout:      10 * time.Second,
		SkipVerify:   false,
		ServerName:   host,
		WarningDays:  30,
		CriticalDays: 7,
	}
}

// Check performs the TLS certificate chain validation.
func (c *Checker) Check() (*ChainResult, error) {
	result := &ChainResult{
		Host:             c.Host,
		Port:             c.Port,
		ExpiryWarnings:   []string{},
		SecurityWarnings: []string{},
	}

	address := fmt.Sprintf("%s:%d", c.Host, c.Port)

	// Dial with timeout
	connectStart := time.Now()
	dialer := &net.Dialer{Timeout: c.Timeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	result.ConnectTime = time.Since(connectStart)
	defer conn.Close()

	// TLS handshake
	tlsConfig := &tls.Config{
		ServerName:         c.ServerName,
		InsecureSkipVerify: true, // We verify manually
	}

	handshakeStart := time.Now()
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	result.HandshakeTime = time.Since(handshakeStart)
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	result.TLSVersion = tlsVersionString(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.ServerName = state.ServerName

	// Analyze cipher suite security
	c.analyzeCipherSecurity(result, state.CipherSuite)

	// Process certificates
	now := time.Now()
	for i, cert := range state.PeerCertificates {
		certInfo := c.processCertificate(cert, now)
		result.Certificates = append(result.Certificates, certInfo)

		// Check expiry warnings
		if certInfo.DaysUntilExpiry < 0 {
			result.ExpiryWarnings = append(result.ExpiryWarnings,
				fmt.Sprintf("Certificate #%d (%s) has EXPIRED", i+1, certInfo.Subject))
		} else if certInfo.DaysUntilExpiry <= c.CriticalDays {
			result.ExpiryWarnings = append(result.ExpiryWarnings,
				fmt.Sprintf("🔴 CRITICAL: Certificate #%d (%s) expires in %d days", i+1, certInfo.Subject, certInfo.DaysUntilExpiry))
		} else if certInfo.DaysUntilExpiry <= c.WarningDays {
			result.ExpiryWarnings = append(result.ExpiryWarnings,
				fmt.Sprintf("🟡 WARNING: Certificate #%d (%s) expires in %d days", i+1, certInfo.Subject, certInfo.DaysUntilExpiry))
		}

		// Check key size
		if certInfo.PublicKeyBits < 2048 && certInfo.PublicKeyAlgorithm == "RSA" {
			result.SecurityWarnings = append(result.SecurityWarnings,
				fmt.Sprintf("Certificate #%d has weak RSA key (%d bits)", i+1, certInfo.PublicKeyBits))
		}

		// Check signature algorithm
		if isWeakSignature(certInfo.SignatureAlgorithm) {
			result.SecurityWarnings = append(result.SecurityWarnings,
				fmt.Sprintf("Certificate #%d uses weak signature algorithm: %s", i+1, certInfo.SignatureAlgorithm))
		}
	}

	// Verify chain
	if !c.SkipVerify {
		opts := x509.VerifyOptions{
			DNSName:       c.ServerName,
			Intermediates: x509.NewCertPool(),
		}

		// Add intermediate certificates
		for _, cert := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		if len(state.PeerCertificates) > 0 {
			_, err := state.PeerCertificates[0].Verify(opts)
			if err != nil {
				result.ChainValid = false
				result.ChainError = err.Error()
				result.Verified = false
				result.VerifyError = err.Error()
			} else {
				result.ChainValid = true
				result.Verified = true
			}
		}
	} else {
		result.ChainValid = true
		result.Verified = true
	}

	// Calculate grade
	result.Grade = c.calculateGrade(result)

	return result, nil
}

// processCertificate extracts information from a certificate.
func (c *Checker) processCertificate(cert *x509.Certificate, now time.Time) Certificate {
	certInfo := Certificate{
		Subject:            cert.Subject.CommonName,
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysUntilExpiry:    int(cert.NotAfter.Sub(now).Hours() / 24),
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		IPAddresses:        cert.IPAddresses,
		IsCA:               cert.IsCA,
		IsSelfSigned:       cert.Subject.CommonName == cert.Issuer.CommonName,
		OCSPServers:        cert.OCSPServer,
		CRLDistribution:    cert.CRLDistributionPoints,
	}

	// Get key size
	switch key := cert.PublicKey.(type) {
	case interface{ Size() int }:
		certInfo.PublicKeyBits = key.Size() * 8
	default:
		// For RSA
		if rsaKey, ok := cert.PublicKey.(interface{ N interface{ BitLen() int } }); ok {
			certInfo.PublicKeyBits = rsaKey.N.BitLen()
		}
	}

	// Key usage
	certInfo.KeyUsage = parseKeyUsage(cert.KeyUsage)
	certInfo.ExtKeyUsage = parseExtKeyUsage(cert.ExtKeyUsage)

	// Fingerprint (SHA-256)
	certInfo.Fingerprint = fmt.Sprintf("%X", sha256Fingerprint(cert.Raw))

	return certInfo
}

// analyzeCipherSecurity checks cipher suite security.
func (c *Checker) analyzeCipherSecurity(result *ChainResult, cipherID uint16) {
	cipherName := tls.CipherSuiteName(cipherID)

	// Check for weak ciphers
	weakPatterns := []string{"RC4", "DES", "3DES", "MD5", "SHA1", "EXPORT", "NULL"}
	for _, pattern := range weakPatterns {
		if strings.Contains(cipherName, pattern) {
			result.SecurityWarnings = append(result.SecurityWarnings,
				fmt.Sprintf("Weak cipher suite: %s (contains %s)", cipherName, pattern))
			break
		}
	}
}

// calculateGrade calculates a security grade.
func (c *Checker) calculateGrade(result *ChainResult) string {
	score := 100

	// TLS version
	switch result.TLSVersion {
	case "TLS 1.3":
		// Perfect
	case "TLS 1.2":
		score -= 5
	case "TLS 1.1":
		score -= 30
	case "TLS 1.0":
		score -= 50
	default:
		score -= 70
	}

	// Chain validation
	if !result.ChainValid {
		score -= 40
	}

	// Expiry warnings
	for _, warning := range result.ExpiryWarnings {
		if strings.Contains(warning, "EXPIRED") {
			score -= 50
		} else if strings.Contains(warning, "CRITICAL") {
			score -= 20
		} else if strings.Contains(warning, "WARNING") {
			score -= 5
		}
	}

	// Security warnings
	score -= len(result.SecurityWarnings) * 10

	// Cap at 0
	if score < 0 {
		score = 0
	}

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

// Helper functions

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

func isWeakSignature(alg string) bool {
	weak := []string{"MD5", "SHA1", "MD2", "MD4"}
	algUpper := strings.ToUpper(alg)
	for _, w := range weak {
		if strings.Contains(algUpper, w) && !strings.Contains(algUpper, "SHA256") && !strings.Contains(algUpper, "SHA384") && !strings.Contains(algUpper, "SHA512") {
			return true
		}
	}
	return false
}

func parseKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	return usages
}

func parseExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	var usages []string
	for _, u := range eku {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		}
	}
	return usages
}

func sha256Fingerprint(data []byte) []byte {
	// Simple SHA-256 without importing crypto/sha256 to keep minimal
	// In real implementation, use crypto/sha256
	// For now, return first 32 bytes as placeholder
	import "crypto/sha256"
	sum := sha256.Sum256(data)
	return sum[:]
}
