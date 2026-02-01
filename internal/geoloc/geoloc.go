// Package geoloc provides IP geolocation and traceroute hop mapping functionality.
package geoloc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GeoInfo contains geolocation information for an IP address.
type GeoInfo struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         int     `json:"asn"`
	ASNOrg      string  `json:"asn_org"`
	ISP         string  `json:"isp"`
	Timezone    string  `json:"timezone"`
	IsPrivate   bool    `json:"is_private"`
	LookupTime  time.Duration
	Error       error
}

// HopGeo represents a traceroute hop with geolocation data.
type HopGeo struct {
	Hop      int
	IP       string
	RTT      time.Duration
	GeoInfo  *GeoInfo
	Hostname string
}

// TracerouteGeo represents a complete geolocated traceroute.
type TracerouteGeo struct {
	Target    string
	Hops      []HopGeo
	TotalHops int
	Countries []string
	StartTime time.Time
	Duration  time.Duration
	TotalDist float64 // Approximate distance in km
}

// Config holds configuration for geolocation lookups.
type Config struct {
	Timeout     time.Duration
	MaxParallel int
	IncludeDNS  bool
	UserAgent   string
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:     10 * time.Second,
		MaxParallel: 5,
		IncludeDNS:  true,
		UserAgent:   "NNS-GeoLoc/1.0",
	}
}

// Client provides IP geolocation functionality.
type Client struct {
	config     Config
	httpClient *http.Client
	cache      map[string]*GeoInfo
	cacheMu    sync.RWMutex
}

// NewClient creates a new geolocation client.
func NewClient(cfg Config) *Client {
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		cache: make(map[string]*GeoInfo),
	}
}

// ipAPIResponse represents the response from ip-api.com
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Timezone    string  `json:"timezone"`
	Query       string  `json:"query"`
}

// IsPrivateIP checks if an IP address is private/internal.
func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// Check for loopback
	if parsed.IsLoopback() {
		return true
	}

	// Check for private ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")},
	}

	for _, r := range privateRanges {
		if bytesCompare(parsed, r.start) >= 0 && bytesCompare(parsed, r.end) <= 0 {
			return true
		}
	}

	return parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast()
}

func bytesCompare(a, b net.IP) int {
	a = a.To4()
	b = b.To4()
	if a == nil || b == nil {
		return 0
	}
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// Lookup performs geolocation lookup for an IP address.
func (c *Client) Lookup(ctx context.Context, ip string) (*GeoInfo, error) {
	// Check cache first
	c.cacheMu.RLock()
	if cached, ok := c.cache[ip]; ok {
		c.cacheMu.RUnlock()
		return cached, nil
	}
	c.cacheMu.RUnlock()

	start := time.Now()

	// Handle private IPs
	if IsPrivateIP(ip) {
		info := &GeoInfo{
			IP:         ip,
			IsPrivate:  true,
			Country:    "Private",
			City:       "Local Network",
			LookupTime: time.Since(start),
		}
		c.cacheResult(ip, info)
		return info, nil
	}

	// Use ip-api.com (free, no API key required)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,timezone,query", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	var apiResp ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if apiResp.Status == "fail" {
		return &GeoInfo{
			IP:         ip,
			Error:      fmt.Errorf("lookup failed: %s", apiResp.Message),
			LookupTime: time.Since(start),
		}, nil
	}

	// Parse ASN from AS string (e.g., "AS15169 Google LLC")
	var asn int
	var asnOrg string
	if apiResp.AS != "" {
		parts := strings.SplitN(apiResp.AS, " ", 2)
		if len(parts) >= 1 && strings.HasPrefix(parts[0], "AS") {
			fmt.Sscanf(parts[0], "AS%d", &asn)
		}
		if len(parts) >= 2 {
			asnOrg = parts[1]
		}
	}

	info := &GeoInfo{
		IP:          apiResp.Query,
		Country:     apiResp.Country,
		CountryCode: apiResp.CountryCode,
		Region:      apiResp.RegionName,
		City:        apiResp.City,
		Latitude:    apiResp.Lat,
		Longitude:   apiResp.Lon,
		ASN:         asn,
		ASNOrg:      asnOrg,
		ISP:         apiResp.ISP,
		Timezone:    apiResp.Timezone,
		IsPrivate:   false,
		LookupTime:  time.Since(start),
	}

	c.cacheResult(ip, info)
	return info, nil
}

func (c *Client) cacheResult(ip string, info *GeoInfo) {
	c.cacheMu.Lock()
	c.cache[ip] = info
	c.cacheMu.Unlock()
}

// LookupBatch performs parallel geolocation lookups for multiple IPs.
func (c *Client) LookupBatch(ctx context.Context, ips []string) map[string]*GeoInfo {
	results := make(map[string]*GeoInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore for parallel limit
	sem := make(chan struct{}, c.config.MaxParallel)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info, err := c.Lookup(ctx, ip)
			mu.Lock()
			if err != nil {
				results[ip] = &GeoInfo{IP: ip, Error: err}
			} else {
				results[ip] = info
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// ReverseDNS performs reverse DNS lookup.
func (c *Client) ReverseDNS(ctx context.Context, ip string) (string, error) {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return "", err
	}
	if len(names) > 0 {
		return strings.TrimSuffix(names[0], "."), nil
	}
	return "", nil
}

// Haversine calculates distance between two lat/lon points in km.
func Haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371 // Earth's radius in km

	dLat := (lat2 - lat1) * 0.0174533 // Convert to radians
	dLon := (lon2 - lon1) * 0.0174533
	lat1Rad := lat1 * 0.0174533
	lat2Rad := lat2 * 0.0174533

	a := sin(dLat/2)*sin(dLat/2) + sin(dLon/2)*sin(dLon/2)*cos(lat1Rad)*cos(lat2Rad)
	c := 2 * atan2(sqrt(a), sqrt(1-a))

	return R * c
}

// Math helpers (avoid importing math for simple ops)
func sin(x float64) float64 {
	// Taylor series approximation
	x = normalizeAngle(x)
	return x - (x*x*x)/6 + (x*x*x*x*x)/120 - (x*x*x*x*x*x*x)/5040
}

func cos(x float64) float64 {
	x = normalizeAngle(x)
	return 1 - (x*x)/2 + (x*x*x*x)/24 - (x*x*x*x*x*x)/720
}

func sqrt(x float64) float64 {
	if x < 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}

func atan2(y, x float64) float64 {
	if x > 0 {
		return atan(y / x)
	}
	if x < 0 && y >= 0 {
		return atan(y/x) + 3.14159265359
	}
	if x < 0 && y < 0 {
		return atan(y/x) - 3.14159265359
	}
	if y > 0 {
		return 3.14159265359 / 2
	}
	return -3.14159265359 / 2
}

func atan(x float64) float64 {
	// Simple approximation
	if x > 1 {
		return 3.14159265359/2 - atan(1/x)
	}
	if x < -1 {
		return -3.14159265359/2 - atan(1/x)
	}
	return x - (x*x*x)/3 + (x*x*x*x*x)/5 - (x*x*x*x*x*x*x)/7
}

func normalizeAngle(x float64) float64 {
	for x > 3.14159265359 {
		x -= 2 * 3.14159265359
	}
	for x < -3.14159265359 {
		x += 2 * 3.14159265359
	}
	return x
}

// FormatLocation returns a formatted location string.
func (g *GeoInfo) FormatLocation() string {
	if g.IsPrivate {
		return "Private Network"
	}
	if g.Error != nil {
		return "Unknown"
	}

	parts := []string{}
	if g.City != "" {
		parts = append(parts, g.City)
	}
	if g.Region != "" {
		parts = append(parts, g.Region)
	}
	if g.Country != "" {
		parts = append(parts, g.Country)
	}

	if len(parts) == 0 {
		return "Unknown"
	}
	return strings.Join(parts, ", ")
}

// CountryFlag returns an emoji flag for the country code.
func (g *GeoInfo) CountryFlag() string {
	if g.CountryCode == "" || len(g.CountryCode) != 2 {
		return "🌐"
	}
	// Convert country code to flag emoji
	code := strings.ToUpper(g.CountryCode)
	return string(rune(0x1F1E6+rune(code[0])-'A')) + string(rune(0x1F1E6+rune(code[1])-'A'))
}
