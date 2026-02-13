// Package asn provides BGP Autonomous System Number lookup via DNS (Team Cymru) and RDAP.
package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ASInfo holds information about an Autonomous System.
type ASInfo struct {
	IP          string   `json:"ip"`
	ASN         int      `json:"asn"`
	ASNString   string   `json:"asn_string"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Country     string   `json:"country"`
	Registry    string   `json:"registry"`
	Prefix      string   `json:"prefix"`
	Allocated   string   `json:"allocated"`
	Prefixes    []string `json:"prefixes,omitempty"`
	Peers       []int    `json:"peers,omitempty"`
	LookupTime  time.Duration
}

// LookupOptions configures an ASN lookup.
type LookupOptions struct {
	Target       string
	Timeout      time.Duration
	FetchRDAP    bool
	ResolvePeers bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() LookupOptions {
	return LookupOptions{
		Timeout:   10 * time.Second,
		FetchRDAP: true,
	}
}

// rdapASNResponse is the relevant subset of the RDAP autnum response.
type rdapASNResponse struct {
	Handle   string `json:"handle"`
	Name     string `json:"name"`
	Country  string `json:"country"`
	StartASN int    `json:"startAutnum"`
	EndASN   int    `json:"endAutnum"`
	Entities []struct {
		VCards []interface{} `json:"vcardArray"`
		Roles  []string      `json:"roles"`
	} `json:"entities"`
}

// Lookup performs an ASN lookup for the given target (IP or hostname).
func Lookup(ctx context.Context, opts LookupOptions) (*ASInfo, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	start := time.Now()

	// Resolve hostname to IP if necessary
	ip := opts.Target
	if net.ParseIP(ip) == nil {
		ips, err := net.DefaultResolver.LookupHost(ctx, opts.Target)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", opts.Target, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for %s", opts.Target)
		}
		ip = ips[0]
	}

	info := &ASInfo{IP: ip}

	// Step 1: Team Cymru DNS lookup for ASN
	if err := lookupCymru(ctx, ip, info); err != nil {
		return nil, fmt.Errorf("cymru lookup: %w", err)
	}

	// Step 2: RDAP lookup for detailed info
	if opts.FetchRDAP && info.ASN > 0 {
		lookupRDAP(ctx, info) // best-effort
	}

	info.LookupTime = time.Since(start)
	return info, nil
}

// lookupCymru performs a Team Cymru DNS-based ASN lookup.
// Query: reversed-ip.origin.asn.cymru.com
func lookupCymru(ctx context.Context, ip string, info *ASInfo) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	var queryName string
	if p4 := parsed.To4(); p4 != nil {
		// IPv4: reverse octets
		octets := strings.Split(p4.String(), ".")
		for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
			octets[i], octets[j] = octets[j], octets[i]
		}
		queryName = strings.Join(octets, ".") + ".origin.asn.cymru.com."
	} else {
		// IPv6: expand and reverse nibbles
		expanded := expandIPv6(parsed)
		queryName = expanded + ".origin6.asn.cymru.com."
	}

	resolver := &net.Resolver{}
	txts, err := resolver.LookupTXT(ctx, queryName)
	if err != nil {
		return fmt.Errorf("TXT lookup %s: %w", queryName, err)
	}

	if len(txts) == 0 {
		return fmt.Errorf("no TXT records for %s", queryName)
	}

	// Parse: "ASN | Prefix | Country | Registry | Allocated"
	// Example: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
	for _, txt := range txts {
		parts := strings.Split(txt, "|")
		if len(parts) < 5 {
			continue
		}
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		var asn int
		fmt.Sscanf(parts[0], "%d", &asn)

		info.ASN = asn
		info.ASNString = fmt.Sprintf("AS%d", asn)
		info.Prefix = parts[1]
		info.Country = parts[2]
		info.Registry = parts[3]
		info.Allocated = parts[4]
		break
	}

	// Get AS name via AS<number>.asn.cymru.com
	if info.ASN > 0 {
		asnQuery := fmt.Sprintf("AS%d.asn.cymru.com.", info.ASN)
		asnTxts, err := resolver.LookupTXT(ctx, asnQuery)
		if err == nil && len(asnTxts) > 0 {
			// Parse: "ASN | Country | Registry | Allocated | Name"
			parts := strings.Split(asnTxts[0], "|")
			if len(parts) >= 5 {
				info.Name = strings.TrimSpace(parts[4])
			}
		}
	}

	return nil
}

// lookupRDAP fetches details from the RDAP autnum endpoint.
func lookupRDAP(ctx context.Context, info *ASInfo) {
	url := fmt.Sprintf("https://rdap.arin.net/registry/autnum/%d", info.ASN)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/rdap+json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}

	var rdap rdapASNResponse
	if err := json.Unmarshal(body, &rdap); err != nil {
		return
	}

	if rdap.Name != "" {
		info.Description = rdap.Name
	}
	if rdap.Country != "" && info.Country == "" {
		info.Country = rdap.Country
	}
}

// expandIPv6 returns the reversed-nibble representation for IPv6.
func expandIPv6(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	var nibbles []string
	for i := len(ip) - 1; i >= 0; i-- {
		nibbles = append(nibbles, fmt.Sprintf("%x", ip[i]&0x0f))
		nibbles = append(nibbles, fmt.Sprintf("%x", ip[i]>>4))
	}
	return strings.Join(nibbles, ".")
}

// LookupBatch performs ASN lookups for multiple targets.
func LookupBatch(ctx context.Context, targets []string, opts LookupOptions) []*ASInfo {
	results := make([]*ASInfo, 0, len(targets))
	for _, target := range targets {
		o := opts
		o.Target = target
		info, err := Lookup(ctx, o)
		if err != nil {
			results = append(results, &ASInfo{
				IP:          target,
				Description: fmt.Sprintf("Error: %v", err),
			})
			continue
		}
		results = append(results, info)
	}
	return results
}

// FormatResult returns a human-readable formatted string for an ASInfo.
func FormatResult(info *ASInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  IP:         %s\n", info.IP))
	sb.WriteString(fmt.Sprintf("  ASN:        %s (%d)\n", info.ASNString, info.ASN))
	sb.WriteString(fmt.Sprintf("  Name:       %s\n", info.Name))
	if info.Description != "" && info.Description != info.Name {
		sb.WriteString(fmt.Sprintf("  Org:        %s\n", info.Description))
	}
	sb.WriteString(fmt.Sprintf("  Prefix:     %s\n", info.Prefix))
	sb.WriteString(fmt.Sprintf("  Country:    %s\n", info.Country))
	sb.WriteString(fmt.Sprintf("  Registry:   %s\n", info.Registry))
	sb.WriteString(fmt.Sprintf("  Allocated:  %s\n", info.Allocated))

	if len(info.Prefixes) > 0 {
		sb.WriteString(fmt.Sprintf("  Prefixes:   %d announced\n", len(info.Prefixes)))
		max := 10
		if len(info.Prefixes) < max {
			max = len(info.Prefixes)
		}
		for _, p := range info.Prefixes[:max] {
			sb.WriteString(fmt.Sprintf("              %s\n", p))
		}
		if len(info.Prefixes) > 10 {
			sb.WriteString(fmt.Sprintf("              ... and %d more\n", len(info.Prefixes)-10))
		}
	}

	if len(info.Peers) > 0 {
		sort.Ints(info.Peers)
		sb.WriteString(fmt.Sprintf("  Peers:      %d upstream\n", len(info.Peers)))
	}

	sb.WriteString(fmt.Sprintf("  Lookup:     %v\n", info.LookupTime.Round(time.Millisecond)))

	return sb.String()
}
