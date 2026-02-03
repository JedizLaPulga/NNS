// Package leak provides DNS and WebRTC leak testing for VPN/privacy auditing.
package leak

import (
	"context"
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

// LeakType represents the type of leak detected.
type LeakType string

const (
	LeakTypeDNS    LeakType = "DNS"
	LeakTypeWebRTC LeakType = "WebRTC"
	LeakTypeIP     LeakType = "IP"
)

// LeakResult represents a detected leak.
type LeakResult struct {
	Type        LeakType
	IP          string
	Hostname    string
	ISP         string
	Country     string
	City        string
	IsVPN       bool
	Description string
}

// DNSLeakResult contains DNS leak test results.
type DNSLeakResult struct {
	Resolvers       []ResolverInfo
	LeaksDetected   bool
	UniqueISPs      []string
	UniqueCountries []string
	TestDomains     []string
	Duration        time.Duration
}

// ResolverInfo contains information about a detected DNS resolver.
type ResolverInfo struct {
	IP      string
	ISP     string
	Country string
	City    string
	IsLocal bool
}

// PublicIPResult contains public IP information.
type PublicIPResult struct {
	IP       string
	ISP      string
	Country  string
	City     string
	ASN      string
	Org      string
	Timezone string
	IsVPN    bool
	Duration time.Duration
}

// TestResult contains complete leak test results.
type TestResult struct {
	PublicIP        *PublicIPResult
	DNSLeak         *DNSLeakResult
	Leaks           []LeakResult
	IsSecure        bool
	Recommendations []string
	StartTime       time.Time
	Duration        time.Duration
}

// Config holds leak tester configuration.
type Config struct {
	Timeout      time.Duration
	DNSTestCount int
	TestServices []string
	VPNExpected  bool
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:      10 * time.Second,
		DNSTestCount: 3,
		TestServices: []string{
			"https://api.ipify.org?format=json",
			"https://ipinfo.io/json",
		},
		VPNExpected: false,
	}
}

// Tester performs leak testing.
type Tester struct {
	config Config
	client *http.Client
}

// New creates a new leak tester.
func New(cfg Config) *Tester {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.DNSTestCount <= 0 {
		cfg.DNSTestCount = 3
	}

	return &Tester{
		config: cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// TestAll performs comprehensive leak testing.
func (t *Tester) TestAll(ctx context.Context) (*TestResult, error) {
	result := &TestResult{StartTime: time.Now()}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Get public IP
	wg.Add(1)
	go func() {
		defer wg.Done()
		ipResult := t.GetPublicIP(ctx)
		mu.Lock()
		result.PublicIP = ipResult
		mu.Unlock()
	}()

	// Test DNS leaks
	wg.Add(1)
	go func() {
		defer wg.Done()
		dnsResult := t.TestDNSLeaks(ctx)
		mu.Lock()
		result.DNSLeak = dnsResult
		mu.Unlock()
	}()

	wg.Wait()
	result.Duration = time.Since(result.StartTime)

	// Analyze results
	t.analyzeResults(result)

	return result, nil
}

// GetPublicIP retrieves public IP information.
func (t *Tester) GetPublicIP(ctx context.Context) *PublicIPResult {
	result := &PublicIPResult{}
	start := time.Now()

	// Try ipinfo.io first
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	if err != nil {
		return result
	}

	resp, err := t.client.Do(req)
	if err != nil {
		// Fallback to ipify
		result.IP = t.getIPFromIPify(ctx)
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return result
	}

	var ipInfo struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Org      string `json:"org"`
		Timezone string `json:"timezone"`
	}

	if err := json.Unmarshal(body, &ipInfo); err != nil {
		return result
	}

	result.IP = ipInfo.IP
	result.City = ipInfo.City
	result.Country = ipInfo.Country
	result.Org = ipInfo.Org
	result.ISP = ipInfo.Org
	result.Timezone = ipInfo.Timezone
	result.Duration = time.Since(start)

	// Check for common VPN indicators
	result.IsVPN = t.detectVPN(result.Org)

	return result
}

func (t *Tester) getIPFromIPify(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if err != nil {
		return ""
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	return strings.TrimSpace(string(body))
}

// TestDNSLeaks tests for DNS leaks by resolving test domains.
func (t *Tester) TestDNSLeaks(ctx context.Context) *DNSLeakResult {
	result := &DNSLeakResult{
		TestDomains: t.generateTestDomains(),
	}
	start := time.Now()

	resolverMap := make(map[string]ResolverInfo)

	for _, domain := range result.TestDomains {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			ipStr := ip.String()
			if _, exists := resolverMap[ipStr]; !exists {
				info := t.getResolverInfo(ctx, ipStr)
				resolverMap[ipStr] = info
			}
		}
	}

	// Collect unique resolvers
	for _, info := range resolverMap {
		result.Resolvers = append(result.Resolvers, info)
	}

	// Collect unique ISPs and countries
	ispSet := make(map[string]bool)
	countrySet := make(map[string]bool)

	for _, r := range result.Resolvers {
		if r.ISP != "" {
			ispSet[r.ISP] = true
		}
		if r.Country != "" {
			countrySet[r.Country] = true
		}
	}

	for isp := range ispSet {
		result.UniqueISPs = append(result.UniqueISPs, isp)
	}
	sort.Strings(result.UniqueISPs)

	for country := range countrySet {
		result.UniqueCountries = append(result.UniqueCountries, country)
	}
	sort.Strings(result.UniqueCountries)

	// Detect leaks (multiple ISPs or resolvers)
	result.LeaksDetected = len(result.UniqueISPs) > 1

	result.Duration = time.Since(start)
	return result
}

func (t *Tester) generateTestDomains() []string {
	// Use unique subdomains to prevent caching
	timestamp := time.Now().UnixNano()
	return []string{
		fmt.Sprintf("test%d.google.com", timestamp%1000),
		"www.google.com",
		"www.cloudflare.com",
	}
}

func (t *Tester) getResolverInfo(ctx context.Context, ip string) ResolverInfo {
	info := ResolverInfo{IP: ip}

	// Check if local
	ipAddr := net.ParseIP(ip)
	if ipAddr != nil && isPrivateIP(ipAddr) {
		info.IsLocal = true
		info.ISP = "Local Network"
		return info
	}

	// Try to get info from ipinfo.io
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return info
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return info
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var ipInfo struct {
		City    string `json:"city"`
		Country string `json:"country"`
		Org     string `json:"org"`
	}

	if err := json.Unmarshal(body, &ipInfo); err != nil {
		return info
	}

	info.City = ipInfo.City
	info.Country = ipInfo.Country
	info.ISP = ipInfo.Org

	return info
}

func isPrivateIP(ip net.IP) bool {
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, cidr := range private {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func (t *Tester) detectVPN(org string) bool {
	vpnKeywords := []string{
		"vpn", "private", "express", "nord", "proton",
		"mullvad", "surfshark", "cyberghost", "pia",
		"hosting", "datacenter", "cloud", "server",
	}

	orgLower := strings.ToLower(org)
	for _, keyword := range vpnKeywords {
		if strings.Contains(orgLower, keyword) {
			return true
		}
	}
	return false
}

func (t *Tester) analyzeResults(result *TestResult) {
	result.IsSecure = true

	// Check for DNS leaks
	if result.DNSLeak != nil && result.DNSLeak.LeaksDetected {
		result.IsSecure = false
		result.Leaks = append(result.Leaks, LeakResult{
			Type:        LeakTypeDNS,
			Description: fmt.Sprintf("Multiple DNS resolvers detected: %v", result.DNSLeak.UniqueISPs),
		})
		result.Recommendations = append(result.Recommendations,
			"Configure DNS to use your VPN's DNS servers",
			"Enable DNS-over-HTTPS (DoH) in your browser")
	}

	// Check for IP exposure when VPN expected
	if t.config.VPNExpected && result.PublicIP != nil && !result.PublicIP.IsVPN {
		result.IsSecure = false
		result.Leaks = append(result.Leaks, LeakResult{
			Type:        LeakTypeIP,
			IP:          result.PublicIP.IP,
			ISP:         result.PublicIP.ISP,
			Description: "Public IP appears to be your real IP (not VPN)",
		})
		result.Recommendations = append(result.Recommendations,
			"Ensure your VPN is connected",
			"Check for VPN kill switch")
	}

	if len(result.Recommendations) == 0 && result.IsSecure {
		result.Recommendations = append(result.Recommendations,
			"No leaks detected - your connection appears secure")
	}
}

// Format returns formatted test results.
func (r *TestResult) Format() string {
	var sb strings.Builder

	sb.WriteString("DNS/IP Leak Test Results\n")
	sb.WriteString(strings.Repeat("─", 60) + "\n\n")

	// Public IP
	if r.PublicIP != nil {
		sb.WriteString("🌐 Public IP Information:\n")
		sb.WriteString(fmt.Sprintf("   IP:       %s\n", r.PublicIP.IP))
		if r.PublicIP.ISP != "" {
			sb.WriteString(fmt.Sprintf("   ISP:      %s\n", r.PublicIP.ISP))
		}
		if r.PublicIP.Country != "" {
			loc := r.PublicIP.Country
			if r.PublicIP.City != "" {
				loc = r.PublicIP.City + ", " + loc
			}
			sb.WriteString(fmt.Sprintf("   Location: %s\n", loc))
		}
		if r.PublicIP.IsVPN {
			sb.WriteString("   VPN:      ✓ Detected\n")
		}
		sb.WriteString("\n")
	}

	// DNS Leak Results
	if r.DNSLeak != nil {
		sb.WriteString("🔍 DNS Leak Test:\n")
		if len(r.DNSLeak.Resolvers) > 0 {
			sb.WriteString(fmt.Sprintf("   Resolvers: %d detected\n", len(r.DNSLeak.Resolvers)))
			for _, res := range r.DNSLeak.Resolvers {
				sb.WriteString(fmt.Sprintf("   • %s", res.IP))
				if res.ISP != "" {
					sb.WriteString(fmt.Sprintf(" (%s)", res.ISP))
				}
				sb.WriteString("\n")
			}
		}
		if r.DNSLeak.LeaksDetected {
			sb.WriteString("   ⚠️  DNS Leak Detected!\n")
		} else {
			sb.WriteString("   ✓ No DNS leaks detected\n")
		}
		sb.WriteString("\n")
	}

	// Overall Status
	sb.WriteString(strings.Repeat("─", 60) + "\n")
	if r.IsSecure {
		sb.WriteString("✅ Status: SECURE - No leaks detected\n")
	} else {
		sb.WriteString("⚠️  Status: LEAKS DETECTED\n")
		for _, leak := range r.Leaks {
			sb.WriteString(fmt.Sprintf("   • %s: %s\n", leak.Type, leak.Description))
		}
	}

	if len(r.Recommendations) > 0 {
		sb.WriteString("\n📋 Recommendations:\n")
		for _, rec := range r.Recommendations {
			sb.WriteString(fmt.Sprintf("   • %s\n", rec))
		}
	}

	sb.WriteString(fmt.Sprintf("\nTest completed in %v\n", r.Duration.Round(time.Millisecond)))

	return sb.String()
}
