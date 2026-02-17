// Package dnsenum discovers subdomains via DNS enumeration (wordlist, zone transfer, reverse).
package dnsenum

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// SubdomainResult holds a discovered subdomain and its records.
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	FQDN      string   `json:"fqdn"`
	IPs       []string `json:"ips"`
	CNAMEs    []string `json:"cnames,omitempty"`
	Source    string   `json:"source"`
}

// ZoneTransferResult holds an AXFR attempt result.
type ZoneTransferResult struct {
	Server  string `json:"server"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Records int    `json:"records"`
}

// Summary holds the full enumeration results.
type Summary struct {
	Domain        string               `json:"domain"`
	Subdomains    []SubdomainResult    `json:"subdomains"`
	ZoneTransfers []ZoneTransferResult `json:"zone_transfers,omitempty"`
	TotalFound    int                  `json:"total_found"`
	TotalChecked  int                  `json:"total_checked"`
	Duration      time.Duration        `json:"duration"`
	Nameservers   []string             `json:"nameservers,omitempty"`
}

// Options configures the DNS enumeration.
type Options struct {
	Domain      string
	Wordlist    []string
	Concurrency int
	Timeout     time.Duration
	TryZoneXfer bool
	Resolver    string
}

// DefaultOptions returns default configuration.
func DefaultOptions(domain string) Options {
	return Options{
		Domain:      domain,
		Wordlist:    DefaultWordlist(),
		Concurrency: 10,
		Timeout:     3 * time.Second,
		TryZoneXfer: true,
	}
}

// DefaultWordlist returns a common subdomain wordlist.
func DefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "smtp", "pop", "imap",
		"webmail", "mx", "ns1", "ns2", "ns3", "ns4",
		"dns", "dns1", "dns2", "api", "dev", "staging",
		"test", "beta", "alpha", "demo", "admin", "panel",
		"vpn", "remote", "gateway", "gw", "proxy",
		"cdn", "static", "assets", "media", "img", "images",
		"app", "mobile", "m", "blog", "shop", "store",
		"secure", "login", "auth", "sso", "portal",
		"db", "database", "sql", "mysql", "postgres",
		"redis", "mongo", "elastic", "search",
		"git", "gitlab", "github", "svn", "repo",
		"ci", "jenkins", "build", "deploy",
		"monitor", "grafana", "prometheus", "kibana", "logs",
		"status", "health", "metrics",
		"docs", "wiki", "help", "support", "kb",
		"cloud", "aws", "azure", "gcp",
		"intranet", "internal", "corp", "office",
		"backup", "bak", "old", "new", "v2",
		"autodiscover", "autoconfig",
		"exchange", "owa", "lync", "teams",
		"calendar", "contacts",
	}
}

// Enumerate performs DNS subdomain enumeration.
func Enumerate(ctx context.Context, opts Options) Summary {
	start := time.Now()
	s := Summary{
		Domain: opts.Domain,
	}

	// Resolve nameservers
	nss, _ := net.LookupNS(opts.Domain)
	for _, ns := range nss {
		s.Nameservers = append(s.Nameservers, strings.TrimSuffix(ns.Host, "."))
	}

	// Try zone transfers
	if opts.TryZoneXfer {
		for _, ns := range s.Nameservers {
			zr := tryZoneTransfer(ns, opts.Domain, opts.Timeout)
			s.ZoneTransfers = append(s.ZoneTransfers, zr)
		}
	}

	// Wordlist brute force
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		found   = make(map[string]SubdomainResult)
		sem     = make(chan struct{}, maxInt(opts.Concurrency, 1))
		checked int
	)

	resolver := buildResolver(opts.Resolver, opts.Timeout)

	for _, word := range opts.Wordlist {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()

			fqdn := sub + "." + opts.Domain

			mu.Lock()
			checked++
			mu.Unlock()

			result := resolveSubdomain(ctx, resolver, sub, fqdn)
			if result != nil {
				mu.Lock()
				found[fqdn] = *result
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()

	// Collect and sort results
	for _, r := range found {
		s.Subdomains = append(s.Subdomains, r)
	}
	sort.Slice(s.Subdomains, func(i, j int) bool {
		return s.Subdomains[i].FQDN < s.Subdomains[j].FQDN
	})

	s.TotalFound = len(s.Subdomains)
	s.TotalChecked = checked
	s.Duration = time.Since(start)
	return s
}

func buildResolver(addr string, timeout time.Duration) *net.Resolver {
	if addr == "" {
		return net.DefaultResolver
	}
	if !strings.Contains(addr, ":") {
		addr = addr + ":53"
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func resolveSubdomain(ctx context.Context, resolver *net.Resolver, sub, fqdn string) *SubdomainResult {
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ips, err := resolver.LookupHost(rctx, fqdn)
	if err != nil {
		return nil
	}
	if len(ips) == 0 {
		return nil
	}

	result := &SubdomainResult{
		Subdomain: sub,
		FQDN:      fqdn,
		IPs:       ips,
		Source:    "wordlist",
	}

	// Check for CNAMEs
	cname, err := resolver.LookupCNAME(rctx, fqdn)
	if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != fqdn {
		result.CNAMEs = append(result.CNAMEs, strings.TrimSuffix(cname, "."))
	}

	return result
}

func tryZoneTransfer(ns, domain string, timeout time.Duration) ZoneTransferResult {
	zr := ZoneTransferResult{Server: ns}

	// Attempt TCP connection for AXFR — most servers will refuse
	addr := ns + ":53"
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		zr.Error = fmt.Sprintf("connection failed: %v", err)
		return zr
	}
	conn.Close()

	// A full AXFR implementation requires DNS wire protocol.
	// We test connectivity only — real zone transfers are rare.
	zr.Error = "connection succeeded but AXFR requires DNS wire protocol (not implemented)"
	return zr
}

// LookupReverseDNS performs reverse DNS lookups for a list of IPs.
func LookupReverseDNS(ctx context.Context, ips []string, timeout time.Duration) map[string][]string {
	results := make(map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			names, err := net.DefaultResolver.LookupAddr(rctx, addr)
			if err != nil || len(names) == 0 {
				return
			}

			clean := make([]string, 0, len(names))
			for _, n := range names {
				clean = append(clean, strings.TrimSuffix(n, "."))
			}

			mu.Lock()
			results[addr] = clean
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// FormatSummary returns a human-readable view of the enumeration results.
func FormatSummary(s Summary) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Domain:       %s\n", s.Domain))
	sb.WriteString(fmt.Sprintf("  Checked:      %d subdomains\n", s.TotalChecked))
	sb.WriteString(fmt.Sprintf("  Found:        %d\n", s.TotalFound))
	sb.WriteString(fmt.Sprintf("  Duration:     %s\n", s.Duration.Round(time.Millisecond)))

	if len(s.Nameservers) > 0 {
		sb.WriteString(fmt.Sprintf("  Nameservers:  %s\n", strings.Join(s.Nameservers, ", ")))
	}

	if len(s.ZoneTransfers) > 0 {
		sb.WriteString("\n  ── Zone Transfer Attempts ──\n")
		for _, zr := range s.ZoneTransfers {
			icon := "✗"
			if zr.Success {
				icon = "✓"
			}
			msg := "refused"
			if zr.Error != "" {
				msg = zr.Error
			}
			if zr.Success {
				msg = fmt.Sprintf("%d records", zr.Records)
			}
			sb.WriteString(fmt.Sprintf("  %s %-30s %s\n", icon, zr.Server, msg))
		}
	}

	if len(s.Subdomains) > 0 {
		sb.WriteString("\n  ── Discovered Subdomains ──\n")
		sb.WriteString(fmt.Sprintf("  %-35s %-20s %s\n", "FQDN", "IP(s)", "CNAME"))
		sb.WriteString(fmt.Sprintf("  %-35s %-20s %s\n",
			"──────────────────────────────────", "───────────────────", "──────"))
		for _, r := range s.Subdomains {
			ips := strings.Join(r.IPs, ", ")
			cnames := "-"
			if len(r.CNAMEs) > 0 {
				cnames = strings.Join(r.CNAMEs, ", ")
			}
			sb.WriteString(fmt.Sprintf("  %-35s %-20s %s\n",
				truncate(r.FQDN, 35), truncate(ips, 20), cnames))
		}
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
