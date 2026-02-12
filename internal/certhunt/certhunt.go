// Package certhunt provides certificate transparency log searching for domain certificates.
package certhunt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// CertEntry represents a certificate found in CT logs.
type CertEntry struct {
	CommonName string
	SANs       []string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	SerialHex  string
	IsExpired  bool
	DaysLeft   int
	IsWildcard bool
	Source     string
}

// Result holds the search results.
type Result struct {
	Domain     string
	Entries    []CertEntry
	LiveCert   *LiveCertInfo
	TotalFound int
	Unique     int
	Expired    int
	Wildcard   int
	StartTime  time.Time
	Duration   time.Duration
	Errors     []string
}

// LiveCertInfo holds info from the live TLS certificate.
type LiveCertInfo struct {
	CommonName string
	SANs       []string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	DaysLeft   int
	SerialHex  string
	Version    int
	SigAlgo    string
	KeyUsage   []string
	IsCA       bool
	ChainLen   int
}

// Format returns formatted results.
func (r *Result) Format() string {
	var b strings.Builder

	b.WriteString("\n╔══════════════════════════════════════════╗\n")
	b.WriteString("║       CERTIFICATE TRANSPARENCY SEARCH    ║\n")
	b.WriteString("╚══════════════════════════════════════════╝\n\n")

	b.WriteString(fmt.Sprintf("  Domain:   %s\n", r.Domain))
	b.WriteString(fmt.Sprintf("  Duration: %v\n\n", r.Duration.Round(time.Millisecond)))

	// Live cert info
	if r.LiveCert != nil {
		b.WriteString("┌─ Live Certificate ─────────────────────────\n")
		b.WriteString(fmt.Sprintf("│  CN:       %s\n", r.LiveCert.CommonName))
		b.WriteString(fmt.Sprintf("│  Issuer:   %s\n", r.LiveCert.Issuer))
		b.WriteString(fmt.Sprintf("│  Valid:    %s → %s\n",
			r.LiveCert.NotBefore.Format("2006-01-02"),
			r.LiveCert.NotAfter.Format("2006-01-02")))
		daysIcon := "🟢"
		if r.LiveCert.DaysLeft < 30 {
			daysIcon = "🔴"
		} else if r.LiveCert.DaysLeft < 90 {
			daysIcon = "🟡"
		}
		b.WriteString(fmt.Sprintf("│  Expires:  %s %d days\n", daysIcon, r.LiveCert.DaysLeft))
		b.WriteString(fmt.Sprintf("│  SigAlgo:  %s\n", r.LiveCert.SigAlgo))
		if len(r.LiveCert.SANs) > 0 {
			b.WriteString(fmt.Sprintf("│  SANs:     %s\n", strings.Join(r.LiveCert.SANs, ", ")))
		}
		b.WriteString(fmt.Sprintf("│  Chain:    %d certificates\n", r.LiveCert.ChainLen))
		b.WriteString("└────────────────────────────────────────────\n\n")
	}

	// CT log summary
	b.WriteString(fmt.Sprintf("  CT Log Certificates: %d found, %d unique\n", r.TotalFound, r.Unique))
	b.WriteString(fmt.Sprintf("  Wildcards: %d  |  Expired: %d\n\n", r.Wildcard, r.Expired))

	if len(r.Entries) > 0 {
		b.WriteString("  ┌──────────────────────── Certificates ────────────────────────\n")
		for i, e := range r.Entries {
			expiry := "🟢"
			if e.IsExpired {
				expiry = "🔴 EXPIRED"
			} else if e.DaysLeft < 30 {
				expiry = fmt.Sprintf("🟡 %dd left", e.DaysLeft)
			} else {
				expiry = fmt.Sprintf("🟢 %dd left", e.DaysLeft)
			}

			wildcard := ""
			if e.IsWildcard {
				wildcard = " [WILDCARD]"
			}

			b.WriteString(fmt.Sprintf("  │ %d. %s%s\n", i+1, e.CommonName, wildcard))
			b.WriteString(fmt.Sprintf("  │    Issuer: %s\n", e.Issuer))
			b.WriteString(fmt.Sprintf("  │    Valid:  %s → %s  %s\n",
				e.NotBefore.Format("2006-01-02"),
				e.NotAfter.Format("2006-01-02"), expiry))
			if len(e.SANs) > 0 && len(e.SANs) <= 5 {
				b.WriteString(fmt.Sprintf("  │    SANs:   %s\n", strings.Join(e.SANs, ", ")))
			} else if len(e.SANs) > 5 {
				b.WriteString(fmt.Sprintf("  │    SANs:   %s (+%d more)\n",
					strings.Join(e.SANs[:5], ", "), len(e.SANs)-5))
			}
			b.WriteString(fmt.Sprintf("  │    Source: %s\n", e.Source))
			if i < len(r.Entries)-1 {
				b.WriteString("  │\n")
			}
		}
		b.WriteString("  └─────────────────────────────────────────────────────────────\n")
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
	live := "no live cert"
	if r.LiveCert != nil {
		live = fmt.Sprintf("live=%dd left", r.LiveCert.DaysLeft)
	}
	return fmt.Sprintf("%s: %d certs found (%d unique, %d wildcard, %d expired) %s [%v]",
		r.Domain, r.TotalFound, r.Unique, r.Wildcard, r.Expired, live,
		r.Duration.Round(time.Millisecond))
}

// Options configures the search.
type Options struct {
	Domain     string
	Timeout    time.Duration
	CheckLive  bool
	MaxResults int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:    15 * time.Second,
		CheckLive:  true,
		MaxResults: 100,
	}
}

// crtShEntry represents a crt.sh API response entry.
type crtShEntry struct {
	ID         int    `json:"id"`
	IssuerName string `json:"issuer_name"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	SerialNum  string `json:"serial_number"`
}

// Searcher performs CT log searches.
type Searcher struct {
	opts   Options
	client *http.Client
}

// NewSearcher creates a new searcher.
func NewSearcher(opts Options) *Searcher {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxResults == 0 {
		opts.MaxResults = 100
	}

	return &Searcher{
		opts: opts,
		client: &http.Client{
			Timeout: opts.Timeout,
		},
	}
}

// Search performs a CT log search for the given domain.
func (s *Searcher) Search(ctx context.Context) (*Result, error) {
	if s.opts.Domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	start := time.Now()
	result := &Result{
		Domain:    s.opts.Domain,
		StartTime: start,
		Entries:   make([]CertEntry, 0),
		Errors:    make([]string, 0),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Search crt.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		entries, err := s.searchCrtSh(ctx)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("crt.sh: %v", err))
			return
		}
		result.Entries = append(result.Entries, entries...)
	}()

	// Check live cert
	if s.opts.CheckLive {
		wg.Add(1)
		go func() {
			defer wg.Done()
			live, err := s.checkLiveCert(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("live cert: %v", err))
				return
			}
			result.LiveCert = live
		}()
	}

	wg.Wait()

	// Deduplicate and sort
	result.Entries = deduplicateEntries(result.Entries)
	sort.Slice(result.Entries, func(i, j int) bool {
		return result.Entries[i].NotAfter.After(result.Entries[j].NotAfter)
	})

	// Enforce max results
	if len(result.Entries) > s.opts.MaxResults {
		result.Entries = result.Entries[:s.opts.MaxResults]
	}

	// Calculate stats
	result.TotalFound = len(result.Entries)
	seen := make(map[string]bool)
	now := time.Now()
	for _, e := range result.Entries {
		if !seen[e.CommonName] {
			seen[e.CommonName] = true
			result.Unique++
		}
		if e.IsExpired {
			result.Expired++
		}
		if e.IsWildcard {
			result.Wildcard++
		}
		_ = now // used above via IsExpired computed at entry creation
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (s *Searcher) searchCrtSh(ctx context.Context) ([]CertEntry, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", s.opts.Domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nns-certhunt/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var raw []crtShEntry
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	now := time.Now()
	entries := make([]CertEntry, 0, len(raw))
	for _, r := range raw {
		notBefore, _ := time.Parse("2006-01-02T15:04:05", r.NotBefore)
		notAfter, _ := time.Parse("2006-01-02T15:04:05", r.NotAfter)

		cn := r.CommonName
		isExpired := notAfter.Before(now)
		daysLeft := 0
		if !isExpired {
			daysLeft = int(notAfter.Sub(now).Hours() / 24)
		}

		sans := parseSANs(r.NameValue)

		entries = append(entries, CertEntry{
			CommonName: cn,
			SANs:       sans,
			Issuer:     extractCN(r.IssuerName),
			NotBefore:  notBefore,
			NotAfter:   notAfter,
			SerialHex:  r.SerialNum,
			IsExpired:  isExpired,
			DaysLeft:   daysLeft,
			IsWildcard: strings.HasPrefix(cn, "*."),
			Source:     "crt.sh",
		})
	}

	return entries, nil
}

func (s *Searcher) checkLiveCert(ctx context.Context) (*LiveCertInfo, error) {
	host := s.opts.Domain
	addr := net.JoinHostPort(host, "443")

	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         host,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := &LiveCertInfo{
		CommonName: cert.Subject.CommonName,
		SANs:       cert.DNSNames,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		DaysLeft:   daysLeft,
		SerialHex:  fmt.Sprintf("%X", cert.SerialNumber),
		Version:    cert.Version,
		SigAlgo:    cert.SignatureAlgorithm.String(),
		IsCA:       cert.IsCA,
		ChainLen:   len(state.PeerCertificates),
		KeyUsage:   describeKeyUsage(cert),
	}

	return info, nil
}

func parseSANs(nameValue string) []string {
	if nameValue == "" {
		return nil
	}
	lines := strings.Split(nameValue, "\n")
	sans := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			sans = append(sans, l)
		}
	}
	return sans
}

func extractCN(issuer string) string {
	parts := strings.Split(issuer, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "CN=") {
			return strings.TrimPrefix(p, "CN=")
		}
	}
	if issuer != "" {
		return issuer
	}
	return "Unknown"
}

func deduplicateEntries(entries []CertEntry) []CertEntry {
	seen := make(map[string]bool)
	result := make([]CertEntry, 0, len(entries))
	for _, e := range entries {
		key := e.CommonName + "|" + e.SerialHex
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	return result
}

func describeKeyUsage(cert *x509.Certificate) []string {
	var usages []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		}
	}
	return usages
}
