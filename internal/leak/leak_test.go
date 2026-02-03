package leak

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 10*time.Second {
		t.Errorf("DefaultConfig().Timeout = %v, want 10s", cfg.Timeout)
	}
	if cfg.DNSTestCount != 3 {
		t.Errorf("DefaultConfig().DNSTestCount = %d, want 3", cfg.DNSTestCount)
	}
	if len(cfg.TestServices) == 0 {
		t.Error("DefaultConfig().TestServices should not be empty")
	}
}

func TestNew(t *testing.T) {
	tester := New(Config{})

	if tester.config.Timeout != 10*time.Second {
		t.Errorf("New().config.Timeout = %v, want 10s", tester.config.Timeout)
	}
	if tester.client == nil {
		t.Error("New() should create HTTP client")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		result := isPrivateIP(ip)
		if result != tt.expected {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
		}
	}
}

func TestDetectVPN(t *testing.T) {
	tester := New(DefaultConfig())

	tests := []struct {
		org      string
		expected bool
	}{
		{"NordVPN", true},
		{"ExpressVPN Inc", true},
		{"ProtonVPN", true},
		{"Comcast Cable", false},
		{"Verizon", false},
		{"AWS Hosting", true},
		{"DigitalOcean Datacenter", true},
	}

	for _, tt := range tests {
		result := tester.detectVPN(tt.org)
		if result != tt.expected {
			t.Errorf("detectVPN(%s) = %v, want %v", tt.org, result, tt.expected)
		}
	}
}

func TestGenerateTestDomains(t *testing.T) {
	tester := New(DefaultConfig())

	domains := tester.generateTestDomains()

	if len(domains) == 0 {
		t.Error("generateTestDomains should return domains")
	}
}

func TestLeakTypes(t *testing.T) {
	if LeakTypeDNS != "DNS" {
		t.Errorf("LeakTypeDNS = %s, want DNS", LeakTypeDNS)
	}
	if LeakTypeWebRTC != "WebRTC" {
		t.Errorf("LeakTypeWebRTC = %s, want WebRTC", LeakTypeWebRTC)
	}
	if LeakTypeIP != "IP" {
		t.Errorf("LeakTypeIP = %s, want IP", LeakTypeIP)
	}
}

func TestAnalyzeResultsSecure(t *testing.T) {
	tester := New(DefaultConfig())

	result := &TestResult{
		PublicIP: &PublicIPResult{
			IP:  "1.2.3.4",
			ISP: "Test ISP",
		},
		DNSLeak: &DNSLeakResult{
			LeaksDetected: false,
		},
	}

	tester.analyzeResults(result)

	if !result.IsSecure {
		t.Error("analyzeResults should set IsSecure = true when no leaks")
	}
}

func TestAnalyzeResultsWithDNSLeak(t *testing.T) {
	tester := New(DefaultConfig())

	result := &TestResult{
		DNSLeak: &DNSLeakResult{
			LeaksDetected: true,
			UniqueISPs:    []string{"ISP1", "ISP2"},
		},
	}

	tester.analyzeResults(result)

	if result.IsSecure {
		t.Error("analyzeResults should set IsSecure = false when DNS leak detected")
	}
	if len(result.Leaks) == 0 {
		t.Error("analyzeResults should add leak entry")
	}
}

func TestTestResultFormat(t *testing.T) {
	result := &TestResult{
		PublicIP: &PublicIPResult{
			IP:      "1.2.3.4",
			ISP:     "Test ISP",
			Country: "US",
			City:    "New York",
		},
		DNSLeak: &DNSLeakResult{
			Resolvers: []ResolverInfo{
				{IP: "8.8.8.8", ISP: "Google"},
			},
			LeaksDetected: false,
		},
		IsSecure: true,
		Duration: 5 * time.Second,
	}

	output := result.Format()

	if output == "" {
		t.Error("Format() returned empty string")
	}
	if len(output) < 100 {
		t.Error("Format() output too short")
	}
}

func TestTestAllTimeout(t *testing.T) {
	cfg := Config{
		Timeout:      500 * time.Millisecond,
		DNSTestCount: 1,
	}
	tester := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := tester.TestAll(ctx)
	if err != nil {
		t.Logf("TestAll returned error: %v", err)
	}
	if result == nil {
		t.Error("TestAll should return result")
	}
}

func TestGetResolverInfoLocal(t *testing.T) {
	tester := New(DefaultConfig())
	ctx := context.Background()

	info := tester.getResolverInfo(ctx, "192.168.1.1")

	if !info.IsLocal {
		t.Error("getResolverInfo should detect local IP")
	}
	if info.IP != "192.168.1.1" {
		t.Errorf("getResolverInfo IP = %s, want 192.168.1.1", info.IP)
	}
}
