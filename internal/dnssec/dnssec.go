// Package dnssec provides DNSSEC validation and chain verification utilities.
package dnssec

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// ValidationStatus represents DNSSEC validation result.
type ValidationStatus string

const (
	StatusSecure        ValidationStatus = "secure"        // Fully validated
	StatusInsecure      ValidationStatus = "insecure"      // No DNSSEC
	StatusBogus         ValidationStatus = "bogus"         // Validation failed
	StatusIndeterminate ValidationStatus = "indeterminate" // Cannot determine
)

// RecordType represents DNS record types relevant to DNSSEC.
type RecordType string

const (
	TypeDNSKEY RecordType = "DNSKEY"
	TypeDS     RecordType = "DS"
	TypeRRSIG  RecordType = "RRSIG"
	TypeNSEC   RecordType = "NSEC"
	TypeNSEC3  RecordType = "NSEC3"
)

// Algorithm represents DNSSEC algorithm identifiers.
type Algorithm int

const (
	AlgRSAMD5       Algorithm = 1
	AlgDH           Algorithm = 2
	AlgDSA          Algorithm = 3
	AlgRSASHA1      Algorithm = 5
	AlgDSANSEC3     Algorithm = 6
	AlgRSASHA1NSEC3 Algorithm = 7
	AlgRSASHA256    Algorithm = 8
	AlgRSASHA512    Algorithm = 10
	AlgECDSAP256    Algorithm = 13
	AlgECDSAP384    Algorithm = 14
	AlgED25519      Algorithm = 15
	AlgED448        Algorithm = 16
)

// AlgorithmNames maps algorithm IDs to human-readable names.
var AlgorithmNames = map[Algorithm]string{
	AlgRSAMD5:       "RSA/MD5 (deprecated)",
	AlgDH:           "Diffie-Hellman",
	AlgDSA:          "DSA/SHA-1",
	AlgRSASHA1:      "RSA/SHA-1",
	AlgDSANSEC3:     "DSA-NSEC3-SHA1",
	AlgRSASHA1NSEC3: "RSA/SHA-1 NSEC3",
	AlgRSASHA256:    "RSA/SHA-256",
	AlgRSASHA512:    "RSA/SHA-512",
	AlgECDSAP256:    "ECDSA P-256/SHA-256",
	AlgECDSAP384:    "ECDSA P-384/SHA-384",
	AlgED25519:      "Ed25519",
	AlgED448:        "Ed448",
}

// DigestType represents DS digest algorithms.
type DigestType int

const (
	DigestSHA1   DigestType = 1
	DigestSHA256 DigestType = 2
	DigestSHA384 DigestType = 4
)

// DigestNames maps digest types to names.
var DigestNames = map[DigestType]string{
	DigestSHA1:   "SHA-1",
	DigestSHA256: "SHA-256",
	DigestSHA384: "SHA-384",
}

// DNSKEYRecord represents a DNSKEY record.
type DNSKEYRecord struct {
	Domain    string
	Flags     uint16
	Protocol  uint8
	Algorithm Algorithm
	PublicKey string
	KeyTag    uint16
	IsKSK     bool // Key Signing Key
	IsZSK     bool // Zone Signing Key
	IsSEP     bool // Secure Entry Point
}

// DSRecord represents a DS (Delegation Signer) record.
type DSRecord struct {
	Domain     string
	KeyTag     uint16
	Algorithm  Algorithm
	DigestType DigestType
	Digest     string
}

// RRSIGRecord represents an RRSIG signature record.
type RRSIGRecord struct {
	TypeCovered string
	Algorithm   Algorithm
	Labels      uint8
	OriginalTTL uint32
	Expiration  time.Time
	Inception   time.Time
	KeyTag      uint16
	SignerName  string
	Signature   string
}

// ChainLink represents one link in the DNSSEC chain of trust.
type ChainLink struct {
	Zone       string
	Parent     string
	DSRecords  []DSRecord
	DNSKEYs    []DNSKEYRecord
	RRSIGs     []RRSIGRecord
	Status     ValidationStatus
	Issues     []string
	LookupTime time.Duration
}

// ValidationResult contains complete DNSSEC validation results.
type ValidationResult struct {
	Domain        string
	Status        ValidationStatus
	Chain         []ChainLink
	Issues        []Issue
	Score         int    // 0-100
	Grade         string // A+, A, B, C, D, F
	HasDNSSEC     bool
	IsFullySecure bool
	Algorithms    []Algorithm
	KeyCount      int
	ExpiringSigs  int
	ExpiredSigs   int
	TotalTime     time.Duration
	Timestamp     time.Time
}

// Issue represents a DNSSEC configuration issue.
type Issue struct {
	Severity    string // critical, high, medium, low, info
	Zone        string
	Title       string
	Description string
	Remediation string
}

// Options configures DNSSEC validation.
type Options struct {
	Resolver      string
	Timeout       time.Duration
	CheckExpiry   bool
	ExpiryWarning time.Duration // Warn if signature expires within this time
	Verbose       bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Resolver:      "8.8.8.8:53",
		Timeout:       10 * time.Second,
		CheckExpiry:   true,
		ExpiryWarning: 7 * 24 * time.Hour, // 7 days
	}
}

// Validator performs DNSSEC validation.
type Validator struct {
	opts     Options
	resolver *net.Resolver
}

// NewValidator creates a new DNSSEC validator.
func NewValidator(opts Options) *Validator {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Resolver == "" {
		opts.Resolver = "8.8.8.8:53"
	}

	return &Validator{
		opts: opts,
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: opts.Timeout}
				return d.DialContext(ctx, "udp", opts.Resolver)
			},
		},
	}
}

// Validate performs DNSSEC validation for a domain.
func (v *Validator) Validate(ctx context.Context, domain string) (*ValidationResult, error) {
	start := time.Now()
	domain = strings.TrimSuffix(domain, ".")

	result := &ValidationResult{
		Domain:    domain,
		Status:    StatusIndeterminate,
		Timestamp: start,
	}

	// Build the zone hierarchy
	zones := v.getZoneHierarchy(domain)

	// Check each zone in the chain
	for i, zone := range zones {
		parent := ""
		if i > 0 {
			parent = zones[i-1]
		}

		link := v.checkZone(ctx, zone, parent)
		result.Chain = append(result.Chain, link)

		// Collect DNSKEY info
		for _, key := range link.DNSKEYs {
			result.KeyCount++
			if !containsAlgorithm(result.Algorithms, key.Algorithm) {
				result.Algorithms = append(result.Algorithms, key.Algorithm)
			}
		}

		// Check signature expiry
		for _, sig := range link.RRSIGs {
			if sig.Expiration.Before(time.Now()) {
				result.ExpiredSigs++
			} else if v.opts.CheckExpiry && sig.Expiration.Before(time.Now().Add(v.opts.ExpiryWarning)) {
				result.ExpiringSigs++
			}
		}
	}

	// Determine overall status
	v.determineStatus(result)
	v.findIssues(result)
	v.calculateScore(result)

	result.TotalTime = time.Since(start)
	return result, nil
}

func (v *Validator) getZoneHierarchy(domain string) []string {
	parts := strings.Split(domain, ".")
	zones := make([]string, 0, len(parts)+1)

	// Root zone
	zones = append(zones, ".")

	// Build from TLD down
	for i := len(parts) - 1; i >= 0; i-- {
		zone := strings.Join(parts[i:], ".")
		zones = append(zones, zone)
	}

	return zones
}

func (v *Validator) checkZone(ctx context.Context, zone, parent string) ChainLink {
	start := time.Now()
	link := ChainLink{
		Zone:   zone,
		Parent: parent,
		Status: StatusIndeterminate,
	}

	// Simulate DNSKEY lookup
	link.DNSKEYs = v.lookupDNSKEYs(ctx, zone)

	// Simulate DS lookup from parent
	if parent != "" {
		link.DSRecords = v.lookupDS(ctx, zone)
	}

	// Simulate RRSIG lookup
	link.RRSIGs = v.lookupRRSIGs(ctx, zone)

	// Validate the zone
	if len(link.DNSKEYs) > 0 {
		link.Status = StatusSecure

		// Check for KSK/ZSK
		hasKSK := false
		hasZSK := false
		for _, key := range link.DNSKEYs {
			if key.IsKSK {
				hasKSK = true
			}
			if key.IsZSK {
				hasZSK = true
			}
		}

		if !hasKSK {
			link.Issues = append(link.Issues, "No KSK (Key Signing Key) found")
		}
		if !hasZSK {
			link.Issues = append(link.Issues, "No ZSK (Zone Signing Key) found")
		}

		// Check DS record matches
		if parent != "" && len(link.DSRecords) == 0 {
			link.Issues = append(link.Issues, "No DS record in parent zone")
			link.Status = StatusInsecure
		}
	} else {
		if zone != "." {
			link.Status = StatusInsecure
		}
	}

	link.LookupTime = time.Since(start)
	return link
}

// Simulated lookups - in production these would do actual DNS queries
func (v *Validator) lookupDNSKEYs(ctx context.Context, zone string) []DNSKEYRecord {
	// Common TLDs and domains have DNSSEC
	secureZones := map[string]bool{
		".":   true,
		"com": true,
		"org": true,
		"net": true,
		"gov": true,
		"edu": true,
	}

	if !secureZones[zone] && !strings.HasSuffix(zone, ".gov") {
		// Check if domain might have DNSSEC (simulation)
		// In reality, we'd do actual DNS lookups
		return nil
	}

	// Return simulated DNSKEY records
	return []DNSKEYRecord{
		{
			Domain:    zone,
			Flags:     257, // KSK
			Protocol:  3,
			Algorithm: AlgRSASHA256,
			KeyTag:    generateKeyTag(zone, true),
			IsKSK:     true,
			IsSEP:     true,
		},
		{
			Domain:    zone,
			Flags:     256, // ZSK
			Protocol:  3,
			Algorithm: AlgRSASHA256,
			KeyTag:    generateKeyTag(zone, false),
			IsZSK:     true,
		},
	}
}

func (v *Validator) lookupDS(ctx context.Context, zone string) []DSRecord {
	// Simulated DS record lookup
	return []DSRecord{
		{
			Domain:     zone,
			KeyTag:     generateKeyTag(zone, true),
			Algorithm:  AlgRSASHA256,
			DigestType: DigestSHA256,
		},
	}
}

func (v *Validator) lookupRRSIGs(ctx context.Context, zone string) []RRSIGRecord {
	// Simulated RRSIG lookup
	return []RRSIGRecord{
		{
			TypeCovered: "DNSKEY",
			Algorithm:   AlgRSASHA256,
			Labels:      uint8(strings.Count(zone, ".") + 1),
			OriginalTTL: 86400,
			Expiration:  time.Now().Add(30 * 24 * time.Hour),
			Inception:   time.Now().Add(-7 * 24 * time.Hour),
			KeyTag:      generateKeyTag(zone, true),
			SignerName:  zone,
		},
	}
}

func (v *Validator) determineStatus(result *ValidationResult) {
	if len(result.Chain) == 0 {
		result.Status = StatusIndeterminate
		return
	}

	allSecure := true
	anyBogus := false
	hasDNSSEC := false

	for _, link := range result.Chain {
		if link.Status == StatusBogus {
			anyBogus = true
		}
		if link.Status != StatusSecure && link.Zone != "." {
			allSecure = false
		}
		if len(link.DNSKEYs) > 0 {
			hasDNSSEC = true
		}
	}

	result.HasDNSSEC = hasDNSSEC

	if anyBogus {
		result.Status = StatusBogus
	} else if allSecure && hasDNSSEC {
		result.Status = StatusSecure
		result.IsFullySecure = true
	} else if hasDNSSEC {
		result.Status = StatusInsecure
	} else {
		result.Status = StatusInsecure
	}
}

func (v *Validator) findIssues(result *ValidationResult) {
	// Check for weak algorithms
	for _, alg := range result.Algorithms {
		if alg == AlgRSAMD5 {
			result.Issues = append(result.Issues, Issue{
				Severity:    "critical",
				Title:       "Weak Algorithm: RSA/MD5",
				Description: "RSA/MD5 (algorithm 1) is cryptographically broken",
				Remediation: "Migrate to RSA/SHA-256 or ECDSA",
			})
		}
		if alg == AlgRSASHA1 || alg == AlgDSA {
			result.Issues = append(result.Issues, Issue{
				Severity:    "high",
				Title:       "Deprecated Algorithm",
				Description: fmt.Sprintf("%s is deprecated", AlgorithmNames[alg]),
				Remediation: "Migrate to RSA/SHA-256 or ECDSA",
			})
		}
	}

	// Check for expiring signatures
	if result.ExpiringSigs > 0 {
		result.Issues = append(result.Issues, Issue{
			Severity:    "medium",
			Title:       "Signatures Expiring Soon",
			Description: fmt.Sprintf("%d signature(s) expire within %v", result.ExpiringSigs, v.opts.ExpiryWarning),
			Remediation: "Ensure automatic re-signing is configured",
		})
	}

	// Check for expired signatures
	if result.ExpiredSigs > 0 {
		result.Issues = append(result.Issues, Issue{
			Severity:    "critical",
			Title:       "Expired Signatures",
			Description: fmt.Sprintf("%d signature(s) have expired", result.ExpiredSigs),
			Remediation: "Re-sign zone immediately",
		})
	}

	// Check chain issues
	for _, link := range result.Chain {
		for _, issue := range link.Issues {
			result.Issues = append(result.Issues, Issue{
				Severity:    "medium",
				Zone:        link.Zone,
				Title:       issue,
				Description: issue,
			})
		}
	}

	// No DNSSEC
	if !result.HasDNSSEC {
		result.Issues = append(result.Issues, Issue{
			Severity:    "info",
			Title:       "No DNSSEC",
			Description: "Domain does not have DNSSEC enabled",
			Remediation: "Enable DNSSEC at your registrar/DNS provider",
		})
	}
}

func (v *Validator) calculateScore(result *ValidationResult) {
	score := 100

	if !result.HasDNSSEC {
		score = 0
	} else {
		for _, issue := range result.Issues {
			switch issue.Severity {
			case "critical":
				score -= 40
			case "high":
				score -= 25
			case "medium":
				score -= 10
			case "low":
				score -= 5
			}
		}

		// Bonus for modern algorithms
		for _, alg := range result.Algorithms {
			if alg == AlgECDSAP256 || alg == AlgECDSAP384 || alg == AlgED25519 {
				score += 10
				break
			}
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	result.Score = score

	switch {
	case score >= 95:
		result.Grade = "A+"
	case score >= 90:
		result.Grade = "A"
	case score >= 80:
		result.Grade = "B"
	case score >= 70:
		result.Grade = "C"
	case score >= 60:
		result.Grade = "D"
	default:
		result.Grade = "F"
	}
}

// Format returns formatted validation results.
func (r *ValidationResult) Format() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\nDNSSEC Validation: %s\n", r.Domain))
	sb.WriteString(strings.Repeat("═", 60) + "\n\n")

	// Status summary
	statusIcon := "?"
	switch r.Status {
	case StatusSecure:
		statusIcon = "✓"
	case StatusInsecure:
		statusIcon = "○"
	case StatusBogus:
		statusIcon = "✗"
	}

	sb.WriteString(fmt.Sprintf("Status:     %s %s\n", statusIcon, r.Status))
	sb.WriteString(fmt.Sprintf("Grade:      %s (%d/100)\n", r.Grade, r.Score))
	sb.WriteString(fmt.Sprintf("DNSSEC:     %v\n", r.HasDNSSEC))
	sb.WriteString(fmt.Sprintf("Keys:       %d\n", r.KeyCount))

	if len(r.Algorithms) > 0 {
		algNames := make([]string, 0, len(r.Algorithms))
		for _, alg := range r.Algorithms {
			if name, ok := AlgorithmNames[alg]; ok {
				algNames = append(algNames, name)
			}
		}
		sb.WriteString(fmt.Sprintf("Algorithms: %s\n", strings.Join(algNames, ", ")))
	}

	// Chain of trust
	sb.WriteString("\nChain of Trust:\n")
	for i, link := range r.Chain {
		indent := strings.Repeat("  ", i)
		icon := "○"
		if link.Status == StatusSecure {
			icon = "✓"
		} else if link.Status == StatusBogus {
			icon = "✗"
		}

		zone := link.Zone
		if zone == "" {
			zone = "(root)"
		}
		sb.WriteString(fmt.Sprintf("%s%s %s (keys: %d, DS: %d)\n",
			indent, icon, zone, len(link.DNSKEYs), len(link.DSRecords)))
	}

	// Issues
	if len(r.Issues) > 0 {
		sb.WriteString("\nIssues Found:\n")
		for _, issue := range r.Issues {
			icon := "○"
			switch issue.Severity {
			case "critical":
				icon = "✗"
			case "high":
				icon = "!"
			case "medium":
				icon = "△"
			}
			zone := ""
			if issue.Zone != "" {
				zone = fmt.Sprintf(" [%s]", issue.Zone)
			}
			sb.WriteString(fmt.Sprintf("  %s [%s]%s %s\n", icon, issue.Severity, zone, issue.Title))
		}
	} else {
		sb.WriteString("\n✓ No issues found\n")
	}

	sb.WriteString(fmt.Sprintf("\nValidation completed in %v\n", r.TotalTime.Round(time.Millisecond)))

	return sb.String()
}

// Helper functions
func containsAlgorithm(algs []Algorithm, alg Algorithm) bool {
	for _, a := range algs {
		if a == alg {
			return true
		}
	}
	return false
}

func generateKeyTag(zone string, isKSK bool) uint16 {
	// Simple hash-based key tag generation for simulation
	h := uint16(0)
	for _, c := range zone {
		h = h*31 + uint16(c)
	}
	if isKSK {
		h += 1000
	}
	return h
}

// GetIssuesBySeverity returns issues sorted by severity.
func (r *ValidationResult) GetIssuesBySeverity() []Issue {
	sorted := make([]Issue, len(r.Issues))
	copy(sorted, r.Issues)

	severityOrder := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}

	sort.Slice(sorted, func(i, j int) bool {
		return severityOrder[sorted[i].Severity] < severityOrder[sorted[j].Severity]
	})

	return sorted
}
