// Package blacklist provides IP/domain reputation checking against multiple blacklists.
package blacklist

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ListType represents the type of blacklist.
type ListType string

const (
	TypeDNSBL ListType = "dnsbl" // DNS-based blacklist (for IPs)
	TypeURIBL ListType = "uribl" // URI blacklist (for domains)
	TypeSURBL ListType = "surbl" // Spam URI blocklist
)

// Blacklist represents a single blacklist service.
type Blacklist struct {
	Name        string
	Zone        string
	Type        ListType
	Description string
	Website     string
	Category    string // spam, malware, phishing, etc.
}

// CommonBlacklists are well-known DNS blacklists.
var CommonBlacklists = []Blacklist{
	// IP-based DNSBLs
	{Name: "Spamhaus ZEN", Zone: "zen.spamhaus.org", Type: TypeDNSBL, Category: "spam", Description: "Combined Spamhaus blocklist"},
	{Name: "Spamhaus SBL", Zone: "sbl.spamhaus.org", Type: TypeDNSBL, Category: "spam", Description: "Spamhaus Block List"},
	{Name: "Spamhaus XBL", Zone: "xbl.spamhaus.org", Type: TypeDNSBL, Category: "exploit", Description: "Exploits Block List"},
	{Name: "Spamcop", Zone: "bl.spamcop.net", Type: TypeDNSBL, Category: "spam", Description: "SpamCop Blocking List"},
	{Name: "Barracuda", Zone: "b.barracudacentral.org", Type: TypeDNSBL, Category: "spam", Description: "Barracuda Reputation"},
	{Name: "SORBS", Zone: "dnsbl.sorbs.net", Type: TypeDNSBL, Category: "spam", Description: "SORBS aggregated list"},
	{Name: "UCEPROTECT L1", Zone: "dnsbl-1.uceprotect.net", Type: TypeDNSBL, Category: "spam", Description: "UCEPROTECT Level 1"},
	{Name: "UCEPROTECT L2", Zone: "dnsbl-2.uceprotect.net", Type: TypeDNSBL, Category: "spam", Description: "UCEPROTECT Level 2"},
	{Name: "SpamRATS", Zone: "noptr.spamrats.com", Type: TypeDNSBL, Category: "spam", Description: "SpamRATS list"},
	{Name: "JustSpam", Zone: "dnsbl.justspam.org", Type: TypeDNSBL, Category: "spam", Description: "JustSpam.org"},
	// Domain-based URIBLs
	{Name: "Spamhaus DBL", Zone: "dbl.spamhaus.org", Type: TypeURIBL, Category: "spam", Description: "Domain Block List"},
	{Name: "SURBL Multi", Zone: "multi.surbl.org", Type: TypeSURBL, Category: "spam", Description: "SURBL combined list"},
	{Name: "URIBL Black", Zone: "black.uribl.com", Type: TypeURIBL, Category: "spam", Description: "URIBL black list"},
}

// ListingResult represents a check result for a single blacklist.
type ListingResult struct {
	Blacklist  Blacklist
	Listed     bool
	ReturnCode string // The A record returned (e.g., 127.0.0.2)
	Reason     string // TXT record explanation
	LookupTime time.Duration
	Error      error
}

// CheckResult contains aggregated blacklist check results.
type CheckResult struct {
	Target      string
	TargetType  string // "ip" or "domain"
	TotalChecks int
	TotalListed int
	Listings    []ListingResult
	CleanLists  []Blacklist
	Score       int    // 0-100 reputation score
	Risk        string // low, medium, high, critical
	StartTime   time.Time
	Duration    time.Duration
	Categories  map[string]int // category -> listing count
}

// Options configures blacklist checking.
type Options struct {
	Blacklists  []Blacklist
	Timeout     time.Duration
	Concurrency int
	IncludeTXT  bool // Query TXT records for reasons
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Blacklists:  CommonBlacklists,
		Timeout:     5 * time.Second,
		Concurrency: 10,
		IncludeTXT:  true,
	}
}

// Checker performs blacklist lookups.
type Checker struct {
	opts     Options
	resolver *net.Resolver
}

// NewChecker creates a new blacklist checker.
func NewChecker(opts Options) *Checker {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if len(opts.Blacklists) == 0 {
		opts.Blacklists = CommonBlacklists
	}

	return &Checker{
		opts:     opts,
		resolver: net.DefaultResolver,
	}
}

// CheckIP checks an IP address against all configured blacklists.
func (c *Checker) CheckIP(ctx context.Context, ip string) (*CheckResult, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Only IPv4 supported for DNSBL
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("IPv6 not supported for DNSBL, use IPv4")
	}

	// Reverse the IP for DNSBL lookup
	reversed := fmt.Sprintf("%d.%d.%d.%d", ipv4[3], ipv4[2], ipv4[1], ipv4[0])

	return c.check(ctx, reversed, ip, "ip", TypeDNSBL)
}

// CheckDomain checks a domain against URI blacklists.
func (c *Checker) CheckDomain(ctx context.Context, domain string) (*CheckResult, error) {
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	domain = strings.Split(domain, "/")[0] // Remove path

	return c.check(ctx, domain, domain, "domain", TypeURIBL)
}

func (c *Checker) check(ctx context.Context, query, target, targetType string, listType ListType) (*CheckResult, error) {
	start := time.Now()
	result := &CheckResult{
		Target:     target,
		TargetType: targetType,
		StartTime:  start,
		Categories: make(map[string]int),
	}

	// Filter blacklists by type
	var applicableLists []Blacklist
	for _, bl := range c.opts.Blacklists {
		if listType == TypeDNSBL && bl.Type == TypeDNSBL {
			applicableLists = append(applicableLists, bl)
		} else if listType == TypeURIBL && (bl.Type == TypeURIBL || bl.Type == TypeSURBL) {
			applicableLists = append(applicableLists, bl)
		}
	}

	result.TotalChecks = len(applicableLists)

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, c.opts.Concurrency)

	for _, bl := range applicableLists {
		wg.Add(1)
		go func(bl Blacklist) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			listing := c.checkSingleList(ctx, query, bl)

			mu.Lock()
			result.Listings = append(result.Listings, listing)
			if listing.Listed {
				result.TotalListed++
				result.Categories[bl.Category]++
			} else if listing.Error == nil {
				result.CleanLists = append(result.CleanLists, bl)
			}
			mu.Unlock()
		}(bl)
	}

	wg.Wait()

	// Sort listings - listed first, then by name
	sort.Slice(result.Listings, func(i, j int) bool {
		if result.Listings[i].Listed != result.Listings[j].Listed {
			return result.Listings[i].Listed
		}
		return result.Listings[i].Blacklist.Name < result.Listings[j].Blacklist.Name
	})

	c.calculateScore(result)
	result.Duration = time.Since(start)

	return result, nil
}

func (c *Checker) checkSingleList(ctx context.Context, query string, bl Blacklist) ListingResult {
	start := time.Now()
	result := ListingResult{
		Blacklist: bl,
	}

	lookupName := query + "." + bl.Zone

	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	// Lookup A record
	ips, err := c.resolver.LookupIP(ctx, "ip4", lookupName)
	result.LookupTime = time.Since(start)

	if err != nil {
		// NXDOMAIN means not listed (this is good)
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Listed = false
			return result
		}
		result.Error = err
		return result
	}

	if len(ips) > 0 {
		result.Listed = true
		result.ReturnCode = ips[0].String()

		// Get TXT record for reason
		if c.opts.IncludeTXT {
			txtRecords, err := c.resolver.LookupTXT(ctx, lookupName)
			if err == nil && len(txtRecords) > 0 {
				result.Reason = strings.Join(txtRecords, " ")
			}
		}
	}

	return result
}

func (c *Checker) calculateScore(result *CheckResult) {
	if result.TotalChecks == 0 {
		result.Score = 100
		result.Risk = "unknown"
		return
	}

	// Base score calculation
	listingRatio := float64(result.TotalListed) / float64(result.TotalChecks)
	result.Score = int(100 * (1 - listingRatio))

	// Adjust for critical lists (Spamhaus carries more weight)
	for _, listing := range result.Listings {
		if listing.Listed {
			if strings.Contains(listing.Blacklist.Name, "Spamhaus") {
				result.Score -= 10
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	// Determine risk level
	switch {
	case result.TotalListed == 0:
		result.Risk = "low"
	case result.TotalListed <= 2:
		result.Risk = "medium"
	case result.TotalListed <= 5:
		result.Risk = "high"
	default:
		result.Risk = "critical"
	}
}

// Format returns formatted check results.
func (r *CheckResult) Format() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\nBlacklist Check: %s (%s)\n", r.Target, r.TargetType))
	sb.WriteString(strings.Repeat("═", 70) + "\n\n")

	// Summary
	riskIcon := "✓"
	switch r.Risk {
	case "medium":
		riskIcon = "△"
	case "high":
		riskIcon = "!"
	case "critical":
		riskIcon = "✗"
	}

	sb.WriteString(fmt.Sprintf("Score:     %d/100\n", r.Score))
	sb.WriteString(fmt.Sprintf("Risk:      %s %s\n", riskIcon, strings.ToUpper(r.Risk)))
	sb.WriteString(fmt.Sprintf("Listings:  %d of %d blacklists\n", r.TotalListed, r.TotalChecks))

	if len(r.Categories) > 0 && r.TotalListed > 0 {
		sb.WriteString("Categories: ")
		cats := make([]string, 0, len(r.Categories))
		for cat, count := range r.Categories {
			cats = append(cats, fmt.Sprintf("%s(%d)", cat, count))
		}
		sb.WriteString(strings.Join(cats, ", ") + "\n")
	}

	// Listings
	if r.TotalListed > 0 {
		sb.WriteString("\n⚠ Listed on:\n")
		for _, listing := range r.Listings {
			if listing.Listed {
				sb.WriteString(fmt.Sprintf("  ✗ %s\n", listing.Blacklist.Name))
				sb.WriteString(fmt.Sprintf("    Zone: %s\n", listing.Blacklist.Zone))
				sb.WriteString(fmt.Sprintf("    Code: %s\n", listing.ReturnCode))
				if listing.Reason != "" {
					reason := listing.Reason
					if len(reason) > 60 {
						reason = reason[:57] + "..."
					}
					sb.WriteString(fmt.Sprintf("    Reason: %s\n", reason))
				}
			}
		}
	}

	// Clean lists summary
	sb.WriteString(fmt.Sprintf("\n✓ Clean on %d lists\n", len(r.CleanLists)))

	// Errors
	errorCount := 0
	for _, listing := range r.Listings {
		if listing.Error != nil {
			errorCount++
		}
	}
	if errorCount > 0 {
		sb.WriteString(fmt.Sprintf("⚠ %d lookup errors\n", errorCount))
	}

	sb.WriteString(fmt.Sprintf("\nCompleted in %v\n", r.Duration.Round(time.Millisecond)))

	return sb.String()
}

// FormatCompact returns a compact summary.
func (r *CheckResult) FormatCompact() string {
	icon := "✓"
	if r.TotalListed > 0 {
		icon = "✗"
	}
	return fmt.Sprintf("%s %s: %d/%d blacklists (%s risk, score %d)",
		icon, r.Target, r.TotalListed, r.TotalChecks, r.Risk, r.Score)
}

// IsClean returns true if the target is not listed on any blacklist.
func (r *CheckResult) IsClean() bool {
	return r.TotalListed == 0
}

// GetListedBlacklists returns only the blacklists where the target is listed.
func (r *CheckResult) GetListedBlacklists() []Blacklist {
	var listed []Blacklist
	for _, l := range r.Listings {
		if l.Listed {
			listed = append(listed, l.Blacklist)
		}
	}
	return listed
}

// CheckMultipleIPs checks multiple IPs concurrently.
func (c *Checker) CheckMultipleIPs(ctx context.Context, ips []string) map[string]*CheckResult {
	results := make(map[string]*CheckResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			result, err := c.CheckIP(ctx, ip)
			mu.Lock()
			if err == nil {
				results[ip] = result
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// ReverseIP reverses an IPv4 address for DNSBL lookup.
func ReverseIP(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP")
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return "", fmt.Errorf("not IPv4")
	}
	return fmt.Sprintf("%d.%d.%d.%d", ipv4[3], ipv4[2], ipv4[1], ipv4[0]), nil
}
