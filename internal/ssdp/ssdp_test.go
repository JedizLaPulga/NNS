package ssdp

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, 3*time.Second)
	}
	if cfg.SearchTarget != DefaultSearchTarget {
		t.Errorf("SearchTarget = %q, want %q", cfg.SearchTarget, DefaultSearchTarget)
	}
	if cfg.MX != 2 {
		t.Errorf("MX = %d, want %d", cfg.MX, 2)
	}
}

func TestNewScanner(t *testing.T) {
	// Test with empty config (should use defaults)
	s := New(Config{})
	if s.config.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want %v", s.config.Timeout, 3*time.Second)
	}
	if s.config.SearchTarget != DefaultSearchTarget {
		t.Errorf("SearchTarget = %q, want %q", s.config.SearchTarget, DefaultSearchTarget)
	}
	if s.config.MX != 2 {
		t.Errorf("MX = %d, want %d", s.config.MX, 2)
	}
}

func TestBuildMSearchRequest(t *testing.T) {
	cfg := DefaultConfig()
	s := New(cfg)

	request := s.buildMSearchRequest()

	// Check required elements
	required := []string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		"MAN: \"ssdp:discover\"",
		"MX:",
		"ST:",
	}

	for _, r := range required {
		if !strings.Contains(request, r) {
			t.Errorf("Request missing %q", r)
		}
	}
}

func TestParseResponse(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\n" +
		"Location: http://192.168.1.1:1900/rootDesc.xml\r\n" +
		"Server: Linux/3.14 UPnP/1.0 Test/1.0\r\n" +
		"USN: uuid:12345678-1234::upnp:rootdevice\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"\r\n"

	device, err := parseResponse([]byte(response))
	if err != nil {
		t.Fatalf("parseResponse() error = %v", err)
	}

	if device.Location != "http://192.168.1.1:1900/rootDesc.xml" {
		t.Errorf("Location = %q, want %q", device.Location, "http://192.168.1.1:1900/rootDesc.xml")
	}
	if !strings.Contains(device.Server, "UPnP") {
		t.Errorf("Server = %q, should contain UPnP", device.Server)
	}
	if device.ST != "upnp:rootdevice" {
		t.Errorf("ST = %q, want %q", device.ST, "upnp:rootdevice")
	}
}

func TestParseRawHeaders(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\n" +
		"LOCATION: http://192.168.1.1/desc.xml\r\n" +
		"SERVER: Test Server\r\n" +
		"USN: uuid:test-123\r\n" +
		"\r\n"

	device, err := parseRawHeaders([]byte(response))
	if err != nil {
		t.Fatalf("parseRawHeaders() error = %v", err)
	}

	if device.Location != "http://192.168.1.1/desc.xml" {
		t.Errorf("Location = %q", device.Location)
	}
}

func TestFormatDevice(t *testing.T) {
	device := Device{
		IP:           "192.168.1.1",
		Server:       "Test Server",
		ST:           "upnp:rootdevice",
		ResponseTime: 50 * time.Millisecond,
	}

	formatted := FormatDevice(device)

	if !strings.Contains(formatted, "192.168.1.1") {
		t.Error("Formatted output should contain IP")
	}
	if !strings.Contains(formatted, "Test Server") {
		t.Error("Formatted output should contain server name")
	}
}

func TestDeviceType(t *testing.T) {
	tests := []struct {
		st   string
		want string
	}{
		{"upnp:rootdevice", "UPnP Root Device"},
		{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "Internet Gateway"},
		{"urn:schemas-upnp-org:device:MediaServer:1", "Media Server"},
		{"urn:schemas-upnp-org:device:MediaRenderer:1", "Media Renderer"},
		{"unknown:device", "unknown:device"},
	}

	for _, tt := range tests {
		t.Run(tt.st, func(t *testing.T) {
			got := DeviceType(tt.st)
			if got != tt.want {
				t.Errorf("DeviceType(%q) = %q, want %q", tt.st, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"this is a long string", 10, "this is..."},
		{"exact", 5, "exact"},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := truncate(tt.s, tt.max)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
			}
		})
	}
}

func TestCommonSearchTargets(t *testing.T) {
	targets := CommonSearchTargets()
	if len(targets) == 0 {
		t.Error("CommonSearchTargets() returned empty slice")
	}

	// Should contain ssdp:all
	found := false
	for _, st := range targets {
		if st == "ssdp:all" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CommonSearchTargets() should include ssdp:all")
	}
}

func TestSortByIP(t *testing.T) {
	devices := []Device{
		{IP: "192.168.1.10"},
		{IP: "192.168.1.1"},
		{IP: "192.168.1.5"},
	}

	SortByIP(devices)

	if devices[0].IP != "192.168.1.1" {
		t.Errorf("First device IP = %q, want 192.168.1.1", devices[0].IP)
	}
}

func TestSortByResponseTime(t *testing.T) {
	devices := []Device{
		{IP: "a", ResponseTime: 100 * time.Millisecond},
		{IP: "b", ResponseTime: 10 * time.Millisecond},
		{IP: "c", ResponseTime: 50 * time.Millisecond},
	}

	SortByResponseTime(devices)

	if devices[0].IP != "b" {
		t.Errorf("First device = %q, want b (fastest)", devices[0].IP)
	}
}

func TestDeduplicateDevices(t *testing.T) {
	devices := []Device{
		{USN: "uuid:1", IP: "192.168.1.1"},
		{USN: "uuid:1", IP: "192.168.1.1"}, // Duplicate
		{USN: "uuid:2", IP: "192.168.1.2"},
	}

	result := deduplicateDevices(devices)

	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2", len(result))
	}
}

// Integration test - requires network
func TestDiscover(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	cfg := Config{
		Timeout:      2 * time.Second,
		SearchTarget: DefaultSearchTarget,
		MX:           1,
	}

	s := New(cfg)
	devices, err := s.Discover()

	// Don't fail if no devices found - that's normal in some environments
	if err != nil {
		t.Logf("Discover error (may be expected): %v", err)
	}

	t.Logf("Found %d devices", len(devices))
	for _, d := range devices {
		t.Logf("  %s", FormatDevice(d))
	}
}
