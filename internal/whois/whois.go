// Package whois provides WHOIS lookup functionality for domains and IPs.
package whois

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// Result holds the parsed WHOIS response.
type Result struct {
	Query        string
	Type         string // "domain" or "ip"
	Server       string
	Registrar    string
	Organization string
	CreatedDate  string
	UpdatedDate  string
	ExpiresDate  string
	NameServers  []string
	Status       []string
	CIDR         string
	NetName      string
	NetRange     string
	Country      string
	Raw          string
	Duration     time.Duration
}

// Client performs WHOIS lookups.
type Client struct {
	Timeout time.Duration
	Server  string // Custom WHOIS server (optional)
}

// NewClient creates a new WHOIS client with defaults.
func NewClient() *Client {
	return &Client{
		Timeout: 10 * time.Second,
	}
}

// Lookup performs a WHOIS query for the given target.
func (c *Client) Lookup(ctx context.Context, target string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Query:       target,
		NameServers: make([]string, 0),
		Status:      make([]string, 0),
	}

	// Determine if target is IP or domain
	if ip := net.ParseIP(target); ip != nil {
		result.Type = "ip"
		return c.lookupIP(ctx, target, result, start)
	}

	result.Type = "domain"
	return c.lookupDomain(ctx, target, result, start)
}

// lookupDomain performs WHOIS lookup for a domain.
func (c *Client) lookupDomain(ctx context.Context, domain string, result *Result, start time.Time) (*Result, error) {
	// Determine WHOIS server
	server := c.Server
	if server == "" {
		server = getWhoisServer(domain)
	}
	result.Server = server

	// Query WHOIS
	raw, err := c.query(ctx, server, domain)
	if err != nil {
		return nil, err
	}
	result.Raw = raw
	result.Duration = time.Since(start)

	// Parse response
	parseDomainWhois(result, raw)

	return result, nil
}

// lookupIP performs WHOIS lookup for an IP address.
func (c *Client) lookupIP(ctx context.Context, ip string, result *Result, start time.Time) (*Result, error) {
	// Use ARIN as default for IP lookups
	server := c.Server
	if server == "" {
		server = "whois.arin.net"
	}
	result.Server = server

	raw, err := c.query(ctx, server, "n + "+ip)
	if err != nil {
		return nil, err
	}
	result.Raw = raw
	result.Duration = time.Since(start)

	// Check for referral to other RIR
	if strings.Contains(raw, "whois.ripe.net") {
		raw2, _ := c.query(ctx, "whois.ripe.net", ip)
		if raw2 != "" {
			result.Raw = raw2
			result.Server = "whois.ripe.net"
		}
	} else if strings.Contains(raw, "whois.apnic.net") {
		raw2, _ := c.query(ctx, "whois.apnic.net", ip)
		if raw2 != "" {
			result.Raw = raw2
			result.Server = "whois.apnic.net"
		}
	}

	parseIPWhois(result, result.Raw)

	return result, nil
}

// query sends a WHOIS query to the specified server.
func (c *Client) query(ctx context.Context, server, query string) (string, error) {
	if !strings.Contains(server, ":") {
		server = server + ":43"
	}

	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %w", server, err)
	}
	defer conn.Close()

	// Set deadline
	deadline := time.Now().Add(c.Timeout)
	conn.SetDeadline(deadline)

	// Send query
	_, err = fmt.Fprintf(conn, "%s\r\n", query)
	if err != nil {
		return "", fmt.Errorf("failed to send query: %w", err)
	}

	// Read response
	var buf strings.Builder
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}
		buf.WriteString(line)
	}

	return buf.String(), nil
}

// getWhoisServer determines the appropriate WHOIS server for a domain.
func getWhoisServer(domain string) string {
	// Extract TLD
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return "whois.iana.org"
	}
	tld := parts[len(parts)-1]

	// Common TLD WHOIS servers
	servers := map[string]string{
		"com":  "whois.verisign-grs.com",
		"net":  "whois.verisign-grs.com",
		"org":  "whois.pir.org",
		"info": "whois.afilias.net",
		"io":   "whois.nic.io",
		"co":   "whois.nic.co",
		"me":   "whois.nic.me",
		"biz":  "whois.biz",
		"us":   "whois.nic.us",
		"uk":   "whois.nic.uk",
		"de":   "whois.denic.de",
		"fr":   "whois.nic.fr",
		"nl":   "whois.domain-registry.nl",
		"eu":   "whois.eu",
		"ru":   "whois.tcinet.ru",
		"cn":   "whois.cnnic.cn",
		"au":   "whois.auda.org.au",
		"ca":   "whois.cira.ca",
		"jp":   "whois.jprs.jp",
		"kr":   "whois.kr",
		"br":   "whois.registro.br",
		"in":   "whois.registry.in",
		"it":   "whois.nic.it",
		"es":   "whois.nic.es",
		"pl":   "whois.dns.pl",
		"se":   "whois.iis.se",
		"no":   "whois.norid.no",
		"fi":   "whois.fi",
		"dk":   "whois.dk-hostmaster.dk",
		"at":   "whois.nic.at",
		"ch":   "whois.nic.ch",
		"be":   "whois.dns.be",
		"nz":   "whois.srs.net.nz",
		"za":   "whois.registry.net.za",
		"mx":   "whois.mx",
		"ar":   "whois.nic.ar",
		"tv":   "whois.nic.tv",
		"cc":   "ccwhois.verisign-grs.com",
		"xyz":  "whois.nic.xyz",
		"app":  "whois.nic.google",
		"dev":  "whois.nic.google",
	}

	if server, ok := servers[tld]; ok {
		return server
	}

	return "whois.iana.org"
}

// parseDomainWhois extracts fields from domain WHOIS response.
func parseDomainWhois(result *Result, raw string) {
	lines := strings.Split(raw, "\n")

	patterns := map[string]*regexp.Regexp{
		"registrar":    regexp.MustCompile(`(?i)Registrar:\s*(.+)`),
		"organization": regexp.MustCompile(`(?i)(?:Registrant Organization|Organization):\s*(.+)`),
		"created":      regexp.MustCompile(`(?i)(?:Creation Date|Created|Created On):\s*(.+)`),
		"updated":      regexp.MustCompile(`(?i)(?:Updated Date|Updated|Last Modified):\s*(.+)`),
		"expires":      regexp.MustCompile(`(?i)(?:Expir(?:y|ation) Date|Expires|Expiration):\s*(.+)`),
		"nameserver":   regexp.MustCompile(`(?i)Name Server:\s*(.+)`),
		"status":       regexp.MustCompile(`(?i)(?:Domain Status|Status):\s*(.+)`),
		"country":      regexp.MustCompile(`(?i)(?:Registrant Country|Country):\s*(.+)`),
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		for key, pattern := range patterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				value := strings.TrimSpace(matches[1])
				switch key {
				case "registrar":
					if result.Registrar == "" {
						result.Registrar = value
					}
				case "organization":
					if result.Organization == "" {
						result.Organization = value
					}
				case "created":
					if result.CreatedDate == "" {
						result.CreatedDate = value
					}
				case "updated":
					if result.UpdatedDate == "" {
						result.UpdatedDate = value
					}
				case "expires":
					if result.ExpiresDate == "" {
						result.ExpiresDate = value
					}
				case "nameserver":
					result.NameServers = append(result.NameServers, strings.ToLower(value))
				case "status":
					result.Status = append(result.Status, value)
				case "country":
					if result.Country == "" {
						result.Country = value
					}
				}
			}
		}
	}
}

// parseIPWhois extracts fields from IP WHOIS response.
func parseIPWhois(result *Result, raw string) {
	lines := strings.Split(raw, "\n")

	patterns := map[string]*regexp.Regexp{
		"organization": regexp.MustCompile(`(?i)(?:OrgName|Organisation|org-name|owner):\s*(.+)`),
		"netname":      regexp.MustCompile(`(?i)(?:NetName|netname):\s*(.+)`),
		"netrange":     regexp.MustCompile(`(?i)(?:NetRange|inetnum):\s*(.+)`),
		"cidr":         regexp.MustCompile(`(?i)CIDR:\s*(.+)`),
		"country":      regexp.MustCompile(`(?i)(?:Country|country):\s*(.+)`),
		"created":      regexp.MustCompile(`(?i)(?:RegDate|created):\s*(.+)`),
		"updated":      regexp.MustCompile(`(?i)(?:Updated|last-modified):\s*(.+)`),
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		for key, pattern := range patterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				value := strings.TrimSpace(matches[1])
				switch key {
				case "organization":
					if result.Organization == "" {
						result.Organization = value
					}
				case "netname":
					if result.NetName == "" {
						result.NetName = value
					}
				case "netrange":
					if result.NetRange == "" {
						result.NetRange = value
					}
				case "cidr":
					if result.CIDR == "" {
						result.CIDR = value
					}
				case "country":
					if result.Country == "" {
						result.Country = value
					}
				case "created":
					if result.CreatedDate == "" {
						result.CreatedDate = value
					}
				case "updated":
					if result.UpdatedDate == "" {
						result.UpdatedDate = value
					}
				}
			}
		}
	}
}

// IsExpired checks if a domain is expired based on WHOIS data.
func (r *Result) IsExpired() bool {
	if r.ExpiresDate == "" {
		return false
	}
	// Try common date formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02",
		"02-Jan-2006",
		"2006/01/02",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, r.ExpiresDate); err == nil {
			return t.Before(time.Now())
		}
	}
	return false
}

// DaysUntilExpiry returns days until domain expires, or -1 if unknown.
func (r *Result) DaysUntilExpiry() int {
	if r.ExpiresDate == "" {
		return -1
	}
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02",
		"02-Jan-2006",
		"2006/01/02",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, r.ExpiresDate); err == nil {
			days := int(time.Until(t).Hours() / 24)
			return days
		}
	}
	return -1
}
