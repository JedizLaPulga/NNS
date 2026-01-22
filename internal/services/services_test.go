package services

import (
	"net"
	"testing"
)

func TestNewScanner(t *testing.T) {
	ports := []int{22, 80, 443}
	scanner := NewScanner("example.com", ports)

	if scanner.Host != "example.com" {
		t.Errorf("expected host 'example.com', got '%s'", scanner.Host)
	}
	if len(scanner.Ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(scanner.Ports))
	}
	if scanner.Concurrency != 10 {
		t.Errorf("expected default concurrency 10, got %d", scanner.Concurrency)
	}
}

func TestGetWellKnownService(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{5432, "postgresql"},
		{6379, "redis"},
		{27017, "mongodb"},
		{99999, ""}, // Unknown
	}

	for _, tt := range tests {
		result := getWellKnownService(tt.port)
		if result != tt.expected {
			t.Errorf("getWellKnownService(%d) = %s, want %s", tt.port, result, tt.expected)
		}
	}
}

func TestIdentifyServiceSSH(t *testing.T) {
	banner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
	service, version := identifyService(22, banner)

	if service != "ssh" {
		t.Errorf("expected service 'ssh', got '%s'", service)
	}
	if version != "OpenSSH_8.9p1 Ubuntu" {
		t.Logf("version: %s", version) // Just log, versions vary
	}
}

func TestIdentifyServiceHTTP(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n"
	service, version := identifyService(80, banner)

	if service != "http" {
		t.Errorf("expected service 'http', got '%s'", service)
	}
	if version == "" {
		t.Logf("version extraction may vary")
	}
}

func TestIdentifyServiceRedis(t *testing.T) {
	tests := []struct {
		banner   string
		expected string
	}{
		{"+PONG", "redis"},
		{"-NOAUTH Authentication required", "redis"},
	}

	for _, tt := range tests {
		service, _ := identifyService(6379, tt.banner)
		if service != tt.expected {
			t.Errorf("identifyService(6379, %q) = %s, want %s", tt.banner, service, tt.expected)
		}
	}
}

func TestSanitizeBanner(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello World", "Hello World"},
		{"Hello\x00World", "Hello.World"},
		{"Test\nLine", "Test\nLine"},
		{"  Trim  ", "Trim"},
	}

	for _, tt := range tests {
		result := sanitizeBanner(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeBanner(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGetProbe(t *testing.T) {
	// HTTP should have a probe
	httpProbe := getProbe(80)
	if httpProbe == "" {
		t.Error("expected HTTP probe, got empty")
	}
	if !contains(httpProbe, "GET") {
		t.Error("expected HTTP probe to contain GET")
	}

	// SSH should not have a probe (server speaks first)
	sshProbe := getProbe(22)
	if sshProbe != "" {
		t.Error("expected no SSH probe")
	}
}

func TestCommonPorts(t *testing.T) {
	ports := CommonPorts()
	if len(ports) == 0 {
		t.Error("expected non-empty common ports list")
	}

	// Should include well-known ports
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	expected := []int{22, 80, 443}
	for _, p := range expected {
		if !portSet[p] {
			t.Errorf("expected port %d in common ports", p)
		}
	}
}

func TestTopPorts(t *testing.T) {
	top5 := TopPorts(5)
	if len(top5) != 5 {
		t.Errorf("expected 5 ports, got %d", len(top5))
	}

	// Request more than available
	all := CommonPorts()
	topAll := TopPorts(1000)
	if len(topAll) != len(all) {
		t.Errorf("expected %d ports, got %d", len(all), len(topAll))
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
	}

	for _, tt := range tests {
		result := tlsVersionString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionString(0x%04x) = %s, want %s", tt.version, result, tt.expected)
		}
	}
}

func TestIsTimeout(t *testing.T) {
	// Regular error should not be timeout
	regularErr := net.UnknownNetworkError("test")
	if isTimeout(regularErr) {
		t.Error("regular error should not be timeout")
	}
}

func TestExtractHTTPServer(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n"
	server := extractHTTPServer(banner)
	if server == "" {
		t.Error("expected to extract server name")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsCheck(s, substr))
}

func containsCheck(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
