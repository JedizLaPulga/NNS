package interfaces

import (
	"net"
	"strings"
	"testing"
)

func TestListAll(t *testing.T) {
	ifaces, err := ListAll()
	if err != nil {
		t.Fatalf("ListAll() error = %v", err)
	}

	// Should have at least one interface (loopback)
	if len(ifaces) == 0 {
		t.Error("ListAll() returned no interfaces, expected at least loopback")
	}

	// Verify loopback exists
	hasLoopback := false
	for _, iface := range ifaces {
		if iface.IsLoopback {
			hasLoopback = true
			break
		}
	}
	if !hasLoopback {
		t.Error("ListAll() did not include loopback interface")
	}
}

func TestListActive(t *testing.T) {
	active, err := ListActive()
	if err != nil {
		t.Fatalf("ListActive() error = %v", err)
	}

	// All returned interfaces should be up
	for _, iface := range active {
		if !iface.IsUp {
			t.Errorf("ListActive() returned inactive interface: %s", iface.Name)
		}
	}
}

func TestGetByName(t *testing.T) {
	// First get all interfaces
	all, err := ListAll()
	if err != nil {
		t.Fatalf("ListAll() error = %v", err)
	}

	if len(all) == 0 {
		t.Skip("No interfaces available for testing")
	}

	// Test getting first interface by name
	first := all[0]
	found, err := GetByName(first.Name)
	if err != nil {
		t.Errorf("GetByName(%q) error = %v", first.Name, err)
	}
	if found.Name != first.Name {
		t.Errorf("GetByName() returned %q, want %q", found.Name, first.Name)
	}

	// Test non-existent interface
	_, err = GetByName("nonexistent_interface_xyz")
	if err == nil {
		t.Error("GetByName() for non-existent interface should return error")
	}
}

func TestGetInterfaceCount(t *testing.T) {
	count, err := GetInterfaceCount()
	if err != nil {
		t.Fatalf("GetInterfaceCount() error = %v", err)
	}

	if count < 1 {
		t.Error("GetInterfaceCount() should return at least 1 (loopback)")
	}

	// Verify count matches ListAll
	all, _ := ListAll()
	if count != len(all) {
		t.Errorf("GetInterfaceCount() = %d, but ListAll() returned %d", count, len(all))
	}
}

func TestInterfaceFields(t *testing.T) {
	ifaces, err := ListAll()
	if err != nil {
		t.Fatalf("ListAll() error = %v", err)
	}

	for _, iface := range ifaces {
		// Name should not be empty
		if iface.Name == "" {
			t.Error("Interface has empty name")
		}

		// Index should be positive
		if iface.Index <= 0 {
			t.Errorf("Interface %s has invalid index: %d", iface.Name, iface.Index)
		}

		// MTU should be reasonable
		if iface.MTU < 0 {
			t.Errorf("Interface %s has negative MTU: %d", iface.Name, iface.MTU)
		}

		// Flags should be set
		if iface.Flags == "" {
			t.Errorf("Interface %s has empty flags", iface.Name)
		}

		// IPv4 addresses should be valid CIDR
		for _, addr := range iface.IPv4Addrs {
			_, _, err := net.ParseCIDR(addr)
			if err != nil {
				t.Errorf("Interface %s has invalid IPv4 address %q: %v", iface.Name, addr, err)
			}
		}

		// IPv6 addresses should be valid CIDR
		for _, addr := range iface.IPv6Addrs {
			_, _, err := net.ParseCIDR(addr)
			if err != nil {
				t.Errorf("Interface %s has invalid IPv6 address %q: %v", iface.Name, addr, err)
			}
		}
	}
}

func TestFormatInterface(t *testing.T) {
	iface := Interface{
		Name:         "eth0",
		Index:        1,
		MTU:          1500,
		Flags:        "up|broadcast|multicast",
		HardwareAddr: "00:11:22:33:44:55",
		IPv4Addrs:    []string{"192.168.1.100/24"},
		IPv6Addrs:    []string{"fe80::1/64"},
		IsUp:         true,
	}

	formatted := FormatInterface(iface)

	// Check for expected content
	if !strings.Contains(formatted, "eth0") {
		t.Error("FormatInterface() missing interface name")
	}
	if !strings.Contains(formatted, "1500") {
		t.Error("FormatInterface() missing MTU")
	}
	if !strings.Contains(formatted, "00:11:22:33:44:55") {
		t.Error("FormatInterface() missing MAC address")
	}
	if !strings.Contains(formatted, "192.168.1.100") {
		t.Error("FormatInterface() missing IPv4 address")
	}
	if !strings.Contains(formatted, "fe80::1") {
		t.Error("FormatInterface() missing IPv6 address")
	}
}

func TestGetLocalIPs(t *testing.T) {
	ips, err := GetLocalIPs()
	if err != nil {
		t.Fatalf("GetLocalIPs() error = %v", err)
	}

	// Should have at least loopback
	hasLoopback := false
	for _, ip := range ips {
		if ip == "127.0.0.1" {
			hasLoopback = true
		}
		// Validate each IP
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("GetLocalIPs() returned invalid IP: %s", ip)
		}
	}

	if !hasLoopback {
		t.Error("GetLocalIPs() should include 127.0.0.1 (loopback)")
	}
}

func TestHasIPv6(t *testing.T) {
	has, err := HasIPv6()
	if err != nil {
		t.Fatalf("HasIPv6() error = %v", err)
	}

	// Just verify it executes without error
	// Result depends on system configuration
	_ = has
}

func TestIsVirtual(t *testing.T) {
	tests := []struct {
		name     string
		iface    Interface
		expected bool
	}{
		{"docker interface", Interface{Name: "docker0"}, true},
		{"veth interface", Interface{Name: "veth123abc"}, true},
		{"virbr interface", Interface{Name: "virbr0"}, true},
		{"wireguard", Interface{Name: "wg0"}, true},
		{"tailscale", Interface{Name: "tailscale0"}, true},
		{"ethernet", Interface{Name: "eth0"}, false},
		{"wifi", Interface{Name: "wlan0"}, false},
		{"loopback", Interface{Name: "lo"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsVirtual(tt.iface)
			if got != tt.expected {
				t.Errorf("IsVirtual(%q) = %v, want %v", tt.iface.Name, got, tt.expected)
			}
		})
	}
}

func TestGetPlatform(t *testing.T) {
	platform := GetPlatform()
	if platform == "" {
		t.Error("GetPlatform() returned empty string")
	}

	// Should be one of the known platforms
	validPlatforms := []string{"windows", "linux", "darwin", "freebsd", "openbsd"}
	valid := false
	for _, p := range validPlatforms {
		if platform == p {
			valid = true
			break
		}
	}
	if !valid {
		t.Logf("GetPlatform() returned %q (uncommon but may be valid)", platform)
	}
}

func TestGetDefaultGatewayInterface(t *testing.T) {
	// This test may fail in isolated environments without network access
	iface, err := GetDefaultGatewayInterface()
	if err != nil {
		t.Skipf("GetDefaultGatewayInterface() error (may be network isolated): %v", err)
	}

	if iface == nil {
		t.Error("GetDefaultGatewayInterface() returned nil interface")
		return
	}

	if iface.Name == "" {
		t.Error("Default gateway interface has empty name")
	}

	if !iface.IsUp {
		t.Error("Default gateway interface is not up")
	}

	if len(iface.IPv4Addrs) == 0 {
		t.Error("Default gateway interface has no IPv4 addresses")
	}
}

func TestLoopbackInterface(t *testing.T) {
	ifaces, err := ListAll()
	if err != nil {
		t.Fatalf("ListAll() error = %v", err)
	}

	var loopback *Interface
	for _, iface := range ifaces {
		if iface.IsLoopback {
			loopback = &iface
			break
		}
	}

	if loopback == nil {
		t.Fatal("No loopback interface found")
	}

	// Loopback should have 127.0.0.1
	has127 := false
	for _, addr := range loopback.IPv4Addrs {
		if strings.HasPrefix(addr, "127.") {
			has127 = true
			break
		}
	}
	if !has127 {
		t.Error("Loopback interface missing 127.x.x.x address")
	}

	// Loopback should be up
	if !loopback.IsUp {
		t.Error("Loopback interface should be up")
	}
}
