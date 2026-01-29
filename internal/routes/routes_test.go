package routes

import (
	"runtime"
	"testing"
	"time"
)

func TestGetRoutes(t *testing.T) {
	table, err := GetRoutes()
	if err != nil {
		t.Fatalf("GetRoutes failed: %v", err)
	}

	if table == nil {
		t.Fatal("expected non-nil routing table")
	}

	if table.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}

	// Should have at least one route on any system
	if len(table.Routes) == 0 {
		t.Error("expected at least one route")
	}
}

func TestGetDefaultGateway(t *testing.T) {
	gateway, err := GetDefaultGateway()
	if err != nil {
		// Some test environments might not have a default gateway
		t.Skipf("No default gateway: %v", err)
	}

	if gateway == "" {
		t.Error("expected non-empty gateway")
	}
}

func TestRoutingTableSummary(t *testing.T) {
	table := &RoutingTable{
		Routes:         make([]Route, 5),
		IPv4Routes:     3,
		IPv6Routes:     2,
		DefaultGateway: "192.168.1.1",
		DefaultIface:   "eth0",
		Timestamp:      time.Now(),
	}

	summary := table.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}

	// Check summary contains key info
	if !containsStr(summary, "5") {
		t.Error("expected total count in summary")
	}
	if !containsStr(summary, "192.168.1.1") {
		t.Error("expected gateway in summary")
	}
}

func TestRoutingTableFilter(t *testing.T) {
	table := &RoutingTable{
		Routes: []Route{
			{Destination: "192.168.1.0", Gateway: "192.168.1.1", Interface: "eth0"},
			{Destination: "10.0.0.0", Gateway: "10.0.0.1", Interface: "eth1"},
			{Destination: "0.0.0.0", Gateway: "192.168.1.1", Interface: "eth0"},
		},
	}

	// Filter by destination
	filtered := table.Filter("192.168")
	if len(filtered) != 2 {
		t.Errorf("expected 2 routes matching '192.168', got %d", len(filtered))
	}

	// Filter by interface
	filtered = table.Filter("eth1")
	if len(filtered) != 1 {
		t.Errorf("expected 1 route matching 'eth1', got %d", len(filtered))
	}

	// No matches
	filtered = table.Filter("nonexistent")
	if len(filtered) != 0 {
		t.Errorf("expected 0 routes matching 'nonexistent', got %d", len(filtered))
	}
}

func TestRoutingTableGetInterfaceRoutes(t *testing.T) {
	table := &RoutingTable{
		Routes: []Route{
			{Destination: "192.168.1.0", Interface: "eth0"},
			{Destination: "10.0.0.0", Interface: "eth1"},
			{Destination: "0.0.0.0", Interface: "eth0"},
		},
	}

	routes := table.GetInterfaceRoutes("eth0")
	if len(routes) != 2 {
		t.Errorf("expected 2 routes for eth0, got %d", len(routes))
	}

	routes = table.GetInterfaceRoutes("eth1")
	if len(routes) != 1 {
		t.Errorf("expected 1 route for eth1, got %d", len(routes))
	}

	routes = table.GetInterfaceRoutes("nonexistent")
	if len(routes) != 0 {
		t.Errorf("expected 0 routes for nonexistent, got %d", len(routes))
	}
}

func TestRouteIsDefault(t *testing.T) {
	route := Route{
		Destination: "0.0.0.0",
		Netmask:     "0.0.0.0",
		Gateway:     "192.168.1.1",
		IsDefault:   true,
	}

	if !route.IsDefault {
		t.Error("expected route to be default")
	}

	route2 := Route{
		Destination: "192.168.1.0",
		Netmask:     "255.255.255.0",
		Gateway:     "192.168.1.1",
		IsDefault:   false,
	}

	if route2.IsDefault {
		t.Error("expected route to not be default")
	}
}

func TestRouteIsHost(t *testing.T) {
	route := Route{
		Destination: "192.168.1.100",
		Netmask:     "255.255.255.255",
		IsHost:      true,
	}

	if !route.IsHost {
		t.Error("expected route to be host route")
	}
}

func TestGatewayInfo(t *testing.T) {
	info := &GatewayInfo{
		IP:        "192.168.1.1",
		Interface: "eth0",
		Reachable: true,
		RTT:       5 * time.Millisecond,
		IsDefault: true,
	}

	if info.IP != "192.168.1.1" {
		t.Errorf("expected IP '192.168.1.1', got '%s'", info.IP)
	}
	if !info.Reachable {
		t.Error("expected reachable to be true")
	}
	if !info.IsDefault {
		t.Error("expected default gateway flag")
	}
}

func TestTestGateway(t *testing.T) {
	// Test with localhost which should be reachable
	info := TestGateway("127.0.0.1", 2*time.Second)

	if info.IP != "127.0.0.1" {
		t.Errorf("expected IP '127.0.0.1', got '%s'", info.IP)
	}

	// Note: Reachability test may fail depending on firewall
	// We just test that it doesn't panic
}

func TestParseLinuxRoute(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	tests := []struct {
		line    string
		isValid bool
		dest    string
	}{
		{"default via 192.168.1.1 dev eth0 proto dhcp metric 100", true, "0.0.0.0/0"},
		{"192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100", true, "192.168.1.0/24"},
		{"", false, ""},
	}

	for _, tt := range tests {
		route := parseLinuxRoute(tt.line)
		if tt.isValid {
			if route == nil {
				t.Errorf("expected valid route for line: %s", tt.line)
				continue
			}
			if route.Destination != tt.dest {
				t.Errorf("expected destination '%s', got '%s'", tt.dest, route.Destination)
			}
		} else {
			if route != nil {
				t.Errorf("expected nil route for empty line")
			}
		}
	}
}

func TestParseWindowsIPv4Route(t *testing.T) {
	tests := []struct {
		line    string
		isValid bool
		dest    string
	}{
		{"0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25", true, "0.0.0.0"},
		{"192.168.1.0    255.255.255.0        On-link     192.168.1.100    281", true, "192.168.1.0"},
		{"Network Destination        Netmask          Gateway       Interface  Metric", false, ""},
		{"===========================================================================", false, ""},
	}

	for _, tt := range tests {
		route := parseWindowsIPv4Route(tt.line)
		if tt.isValid {
			if route == nil {
				t.Errorf("expected valid route for line: %s", tt.line)
				continue
			}
			if route.Destination != tt.dest {
				t.Errorf("expected destination '%s', got '%s'", tt.dest, route.Destination)
			}
		} else {
			if route != nil {
				t.Errorf("expected nil route for line: %s", tt.line)
			}
		}
	}
}

// Helper function
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStrHelper(s, substr))
}

func containsStrHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
