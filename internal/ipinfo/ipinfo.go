// Package ipinfo provides IP geolocation and ASN information lookup.
package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Info holds IP geolocation and network information.
type Info struct {
	IP          string
	Hostname    string
	City        string
	Region      string
	Country     string
	CountryCode string
	Postal      string
	Location    string
	Timezone    string
	ASN         string
	Org         string
	ISP         string
	IsPrivate   bool
	IsBogon     bool
	Duration    time.Duration
}

// Client performs IP info lookups.
type Client struct {
	Timeout    time.Duration
	HTTPClient *http.Client
}

// NewClient creates a new IP info client.
func NewClient() *Client {
	return &Client{
		Timeout: 10 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Lookup retrieves information about an IP address.
func (c *Client) Lookup(ctx context.Context, ip string) (*Info, error) {
	start := time.Now()

	// Check for private/bogon IP
	if ip == "" || ip == "me" {
		return c.lookupMyIP(ctx, start)
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	info := &Info{
		IP:        ip,
		IsPrivate: isPrivateIP(parsedIP),
		IsBogon:   isBogonIP(parsedIP),
	}

	if info.IsPrivate || info.IsBogon {
		info.Duration = time.Since(start)
		if info.IsPrivate {
			info.Org = "Private Network"
		} else {
			info.Org = "Bogon/Reserved"
		}
		// Try reverse DNS
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			info.Hostname = names[0]
		}
		return info, nil
	}

	// Query public IP info service
	return c.queryIPInfo(ctx, ip, start)
}

// lookupMyIP gets info for the client's public IP.
func (c *Client) lookupMyIP(ctx context.Context, start time.Time) (*Info, error) {
	return c.queryIPInfo(ctx, "", start)
}

// queryIPInfo queries ip-api.com for IP information.
func (c *Client) queryIPInfo(ctx context.Context, ip string, start time.Time) (*Info, error) {
	// Using ip-api.com (free, no API key required)
	url := "http://ip-api.com/json/"
	if ip != "" {
		url += ip
	}
	url += "?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"region"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Timezone    string  `json:"timezone"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		Query       string  `json:"query"`
		Reverse     string  `json:"reverse"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Status != "success" {
		return nil, fmt.Errorf("lookup failed: %s", result.Message)
	}

	info := &Info{
		IP:          result.Query,
		Hostname:    result.Reverse,
		City:        result.City,
		Region:      result.RegionName,
		Country:     result.Country,
		CountryCode: result.CountryCode,
		Postal:      result.Zip,
		Location:    fmt.Sprintf("%.4f, %.4f", result.Lat, result.Lon),
		Timezone:    result.Timezone,
		ISP:         result.ISP,
		Org:         result.Org,
		Duration:    time.Since(start),
	}

	// Parse ASN from AS field (format: "AS12345 Organization Name")
	if result.AS != "" {
		parts := strings.SplitN(result.AS, " ", 2)
		info.ASN = parts[0]
	}

	return info, nil
}

// GetMyIP returns the public IP address.
func GetMyIP(ctx context.Context) (string, error) {
	client := NewClient()
	info, err := client.Lookup(ctx, "")
	if err != nil {
		return "", err
	}
	return info.IP, nil
}

// isPrivateIP checks if an IP is in a private range.
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if ip4[0] == 127 {
			return true
		}
	}
	return false
}

// isBogonIP checks if an IP is a bogon (non-routable) address.
func isBogonIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 0.0.0.0/8
		if ip4[0] == 0 {
			return true
		}
		// 100.64.0.0/10 (Carrier-grade NAT)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		// 169.254.0.0/16 (Link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 192.0.0.0/24 (IETF Protocol Assignments)
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
			return true
		}
		// 192.0.2.0/24 (TEST-NET-1)
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return true
		}
		// 198.51.100.0/24 (TEST-NET-2)
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return true
		}
		// 203.0.113.0/24 (TEST-NET-3)
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true
		}
		// 224.0.0.0/4 (Multicast)
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true
		}
		// 240.0.0.0/4 (Reserved)
		if ip4[0] >= 240 {
			return true
		}
	}
	return false
}

// CountryFlag returns emoji flag for a country code.
func CountryFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	code = strings.ToUpper(code)
	// Convert country code to regional indicator symbols
	r1 := rune(code[0]) - 'A' + 0x1F1E6
	r2 := rune(code[1]) - 'A' + 0x1F1E6
	return string([]rune{r1, r2})
}
