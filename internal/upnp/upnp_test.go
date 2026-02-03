package upnp

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 3*time.Second {
		t.Errorf("DefaultConfig().Timeout = %v, want 3s", cfg.Timeout)
	}
	if cfg.SearchTarget != "ssdp:all" {
		t.Errorf("DefaultConfig().SearchTarget = %s, want ssdp:all", cfg.SearchTarget)
	}
	if !cfg.FetchDetails {
		t.Error("DefaultConfig().FetchDetails should be true")
	}
}

func TestNew(t *testing.T) {
	scanner := New(Config{})

	if scanner.config.Timeout != 3*time.Second {
		t.Errorf("New().config.Timeout = %v, want 3s", scanner.config.Timeout)
	}
	if scanner.client == nil {
		t.Error("New() should create HTTP client")
	}
}

func TestBuildMSearch(t *testing.T) {
	scanner := New(DefaultConfig())
	request := scanner.buildMSearch()

	if !contains(request, "M-SEARCH") {
		t.Error("buildMSearch should contain M-SEARCH")
	}
	if !contains(request, "ssdp:all") {
		t.Error("buildMSearch should contain search target")
	}
	if !contains(request, SSDPMulticastAddr) {
		t.Error("buildMSearch should contain multicast address")
	}
}

func TestParseResponse(t *testing.T) {
	scanner := New(DefaultConfig())

	response := "HTTP/1.1 200 OK\r\n" +
		"LOCATION: http://192.168.1.1:80/desc.xml\r\n" +
		"SERVER: Linux/3.0 UPnP/1.0\r\n" +
		"USN: uuid:12345::upnp:rootdevice\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"\r\n"

	device := scanner.parseResponse([]byte(response), "192.168.1.1")

	if device.IP != "192.168.1.1" {
		t.Errorf("device.IP = %s, want 192.168.1.1", device.IP)
	}
	if device.Location != "http://192.168.1.1:80/desc.xml" {
		t.Errorf("device.Location = %s, want http://192.168.1.1:80/desc.xml", device.Location)
	}
	if device.Server != "Linux/3.0 UPnP/1.0" {
		t.Errorf("device.Server = %s", device.Server)
	}
	if device.ST != "upnp:rootdevice" {
		t.Errorf("device.ST = %s, want upnp:rootdevice", device.ST)
	}
}

func TestFormatDeviceType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "InternetGatewayDevice"},
		{"urn:schemas-upnp-org:device:MediaServer:1", "MediaServer"},
		{"simple", "simple"},
	}

	for _, tt := range tests {
		result := formatDeviceType(tt.input)
		if result != tt.expected {
			t.Errorf("formatDeviceType(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestCommonSearchTargets(t *testing.T) {
	targets := CommonSearchTargets()

	if len(targets) == 0 {
		t.Error("CommonSearchTargets should not be empty")
	}

	hasSSDPAll := false
	for _, target := range targets {
		if target == "ssdp:all" {
			hasSSDPAll = true
			break
		}
	}

	if !hasSSDPAll {
		t.Error("CommonSearchTargets should contain ssdp:all")
	}
}

func TestScanResultFormat(t *testing.T) {
	result := &ScanResult{
		Devices: []Device{
			{
				IP:           "192.168.1.1",
				FriendlyName: "Test Router",
				Manufacturer: "Test Corp",
				ModelName:    "Model-X",
				ResponseTime: 50 * time.Millisecond,
			},
		},
		UniqueDevices: 1,
		Duration:      1 * time.Second,
	}

	output := result.Format()

	if output == "" {
		t.Error("Format() returned empty string")
	}
	if !contains(output, "Test Router") {
		t.Error("Format() should contain device name")
	}
}

func TestScanResultFormatEmpty(t *testing.T) {
	result := &ScanResult{
		Devices:  []Device{},
		Duration: 1 * time.Second,
	}

	output := result.Format()

	if !contains(output, "No UPnP devices found") {
		t.Error("Format() should indicate no devices found")
	}
}

func TestScanTimeout(t *testing.T) {
	cfg := Config{
		Timeout:      100 * time.Millisecond,
		FetchDetails: false,
	}
	scanner := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result, err := scanner.Scan(ctx)
	if err != nil {
		t.Errorf("Scan returned error: %v", err)
	}
	if result == nil {
		t.Error("Scan should return result even if no devices found")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
