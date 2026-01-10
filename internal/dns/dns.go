// Package dns provides DNS lookup functionality with support for multiple record types.
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// RecordType represents DNS record types.
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeNS    RecordType = "NS"
	TypeCNAME RecordType = "CNAME"
	TypePTR   RecordType = "PTR"
	TypeSOA   RecordType = "SOA"
)

// AllTypes returns all supported record types for --all flag.
func AllTypes() []RecordType {
	return []RecordType{TypeA, TypeAAAA, TypeMX, TypeTXT, TypeNS, TypeCNAME, TypeSOA}
}

// GlobalResolvers are well-known public DNS servers for propagation checking.
var GlobalResolvers = []struct {
	Name   string
	Server string
}{
	{"Google", "8.8.8.8"},
	{"Cloudflare", "1.1.1.1"},
	{"Quad9", "9.9.9.9"},
	{"OpenDNS", "208.67.222.222"},
	{"Level3", "4.2.2.1"},
}

// Record represents a single DNS record.
type Record struct {
	Type     RecordType
	Value    string
	Priority int // For MX records
}

// SOARecord represents SOA (Start of Authority) record details.
type SOARecord struct {
	PrimaryNS  string
	AdminEmail string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	MinTTL     uint32
}

// Result holds the result of a DNS query.
type Result struct {
	Type     RecordType
	Records  []Record
	SOA      *SOARecord // Only set for SOA queries
	Duration time.Duration
	Server   string
	Error    error
}

// PropagationResult holds results from multiple DNS servers.
type PropagationResult struct {
	Target  string
	Type    RecordType
	Results []struct {
		Resolver string
		Name     string
		Records  []Record
		Duration time.Duration
		Error    error
	}
}

// Resolver performs DNS lookups.
type Resolver struct {
	Server  string // e.g., "8.8.8.8:53" or empty for system default
	Timeout time.Duration
}

// NewResolver creates a new Resolver with default settings.
func NewResolver() *Resolver {
	return &Resolver{
		Timeout: 5 * time.Second,
	}
}

// SetServer sets a custom DNS server (e.g., "8.8.8.8" or "1.1.1.1").
func (r *Resolver) SetServer(server string) {
	if server != "" && !strings.Contains(server, ":") {
		server = server + ":53"
	}
	r.Server = server
}

// getResolver returns a net.Resolver configured for custom server if set.
func (r *Resolver) getResolver() *net.Resolver {
	if r.Server == "" {
		return net.DefaultResolver
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.Timeout}
			return d.DialContext(ctx, "udp", r.Server)
		},
	}
}

// Lookup performs a DNS lookup for the specified record type.
func (r *Resolver) Lookup(ctx context.Context, name string, recordType RecordType) *Result {
	result := &Result{
		Type:   recordType,
		Server: r.Server,
	}

	if result.Server == "" {
		result.Server = "system"
	}

	start := time.Now()

	switch recordType {
	case TypeA:
		result.Records, result.Error = r.lookupA(ctx, name)
	case TypeAAAA:
		result.Records, result.Error = r.lookupAAAA(ctx, name)
	case TypeMX:
		result.Records, result.Error = r.lookupMX(ctx, name)
	case TypeTXT:
		result.Records, result.Error = r.lookupTXT(ctx, name)
	case TypeNS:
		result.Records, result.Error = r.lookupNS(ctx, name)
	case TypeCNAME:
		result.Records, result.Error = r.lookupCNAME(ctx, name)
	case TypePTR:
		result.Records, result.Error = r.lookupPTR(ctx, name)
	default:
		result.Error = fmt.Errorf("unsupported record type: %s", recordType)
	}

	result.Duration = time.Since(start)
	return result
}

// LookupAll queries all common record types.
func (r *Resolver) LookupAll(ctx context.Context, name string) []Result {
	types := AllTypes()
	results := make([]Result, 0, len(types))

	for _, t := range types {
		res := r.Lookup(ctx, name, t)
		results = append(results, *res)
	}

	return results
}

func (r *Resolver) lookupA(ctx context.Context, name string) ([]Record, error) {
	resolver := r.getResolver()
	ips, err := resolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		return nil, err
	}

	records := make([]Record, len(ips))
	for i, ip := range ips {
		records[i] = Record{Type: TypeA, Value: ip.String()}
	}
	return records, nil
}

func (r *Resolver) lookupAAAA(ctx context.Context, name string) ([]Record, error) {
	resolver := r.getResolver()
	ips, err := resolver.LookupIP(ctx, "ip6", name)
	if err != nil {
		return nil, err
	}

	records := make([]Record, len(ips))
	for i, ip := range ips {
		records[i] = Record{Type: TypeAAAA, Value: ip.String()}
	}
	return records, nil
}

func (r *Resolver) lookupMX(ctx context.Context, name string) ([]Record, error) {
	resolver := r.getResolver()
	mxs, err := resolver.LookupMX(ctx, name)
	if err != nil {
		return nil, err
	}

	records := make([]Record, len(mxs))
	for i, mx := range mxs {
		records[i] = Record{
			Type:     TypeMX,
			Value:    mx.Host,
			Priority: int(mx.Pref),
		}
	}
	return records, nil
}

func (r *Resolver) lookupTXT(ctx context.Context, name string) ([]Record, error) {
	resolver := r.getResolver()
	txts, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, err
	}

	records := make([]Record, len(txts))
	for i, txt := range txts {
		records[i] = Record{Type: TypeTXT, Value: txt}
	}
	return records, nil
}

func (r *Resolver) lookupNS(ctx context.Context, name string) ([]Record, error) {
	resolver := r.getResolver()
	nss, err := resolver.LookupNS(ctx, name)
	if err != nil {
		return nil, err
	}

	records := make([]Record, len(nss))
	for i, ns := range nss {
		records[i] = Record{Type: TypeNS, Value: ns.Host}
	}
	return records, nil
}

func (r *Resolver) lookupCNAME(ctx context.Context, name string) ([]Record, error) {
	resolver := r.getResolver()
	cname, err := resolver.LookupCNAME(ctx, name)
	if err != nil {
		return nil, err
	}

	return []Record{{Type: TypeCNAME, Value: cname}}, nil
}

func (r *Resolver) lookupPTR(ctx context.Context, ip string) ([]Record, error) {
	resolver := r.getResolver()
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil, err
	}

	records := make([]Record, len(names))
	for i, name := range names {
		records[i] = Record{Type: TypePTR, Value: name}
	}
	return records, nil
}

// ParseRecordType converts a string to RecordType.
func ParseRecordType(s string) (RecordType, error) {
	switch strings.ToUpper(s) {
	case "A":
		return TypeA, nil
	case "AAAA":
		return TypeAAAA, nil
	case "MX":
		return TypeMX, nil
	case "TXT":
		return TypeTXT, nil
	case "NS":
		return TypeNS, nil
	case "CNAME":
		return TypeCNAME, nil
	case "PTR":
		return TypePTR, nil
	default:
		return "", fmt.Errorf("unknown record type: %s (valid: A, AAAA, MX, TXT, NS, CNAME, PTR)", s)
	}
}

// IsIPAddress checks if a string is a valid IP address.
func IsIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}
