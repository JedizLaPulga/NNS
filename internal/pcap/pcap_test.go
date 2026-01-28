package pcap

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.SnapLen != 65535 {
		t.Errorf("expected SnapLen 65535, got %d", opts.SnapLen)
	}
	if opts.Promiscuous {
		t.Error("promiscuous should be false by default")
	}
	if opts.Timeout != time.Second {
		t.Errorf("expected Timeout 1s, got %v", opts.Timeout)
	}
}

func TestFilter_MatchesProtocol(t *testing.T) {
	tests := []struct {
		name     string
		filter   Filter
		packet   Packet
		expected bool
	}{
		{
			name:     "no filter matches all",
			filter:   Filter{},
			packet:   Packet{Protocol: "TCP"},
			expected: true,
		},
		{
			name:     "TCP filter matches TCP",
			filter:   Filter{Protocol: "TCP"},
			packet:   Packet{Protocol: "TCP"},
			expected: true,
		},
		{
			name:     "TCP filter case insensitive",
			filter:   Filter{Protocol: "tcp"},
			packet:   Packet{Protocol: "TCP"},
			expected: true,
		},
		{
			name:     "TCP filter rejects UDP",
			filter:   Filter{Protocol: "TCP"},
			packet:   Packet{Protocol: "UDP"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Capture{opts: CaptureOptions{Filter: tt.filter}}
			if got := c.matchesFilter(tt.packet); got != tt.expected {
				t.Errorf("matchesFilter() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFilter_MatchesPort(t *testing.T) {
	tests := []struct {
		name     string
		filter   Filter
		packet   Packet
		expected bool
	}{
		{
			name:     "port filter matches src port",
			filter:   Filter{Port: 443},
			packet:   Packet{SrcPort: 443, DstPort: 52000},
			expected: true,
		},
		{
			name:     "port filter matches dst port",
			filter:   Filter{Port: 443},
			packet:   Packet{SrcPort: 52000, DstPort: 443},
			expected: true,
		},
		{
			name:     "port filter rejects non-matching",
			filter:   Filter{Port: 443},
			packet:   Packet{SrcPort: 52000, DstPort: 80},
			expected: false,
		},
		{
			name:     "src port filter",
			filter:   Filter{SrcPort: 443},
			packet:   Packet{SrcPort: 443, DstPort: 52000},
			expected: true,
		},
		{
			name:     "dst port filter",
			filter:   Filter{DstPort: 80},
			packet:   Packet{SrcPort: 52000, DstPort: 80},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Capture{opts: CaptureOptions{Filter: tt.filter}}
			if got := c.matchesFilter(tt.packet); got != tt.expected {
				t.Errorf("matchesFilter() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFilter_MatchesSize(t *testing.T) {
	tests := []struct {
		name     string
		filter   Filter
		packet   Packet
		expected bool
	}{
		{
			name:     "min size filter passes",
			filter:   Filter{MinSize: 100},
			packet:   Packet{Length: 150},
			expected: true,
		},
		{
			name:     "min size filter fails",
			filter:   Filter{MinSize: 100},
			packet:   Packet{Length: 50},
			expected: false,
		},
		{
			name:     "max size filter passes",
			filter:   Filter{MaxSize: 1500},
			packet:   Packet{Length: 1000},
			expected: true,
		},
		{
			name:     "max size filter fails",
			filter:   Filter{MaxSize: 1500},
			packet:   Packet{Length: 2000},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Capture{opts: CaptureOptions{Filter: tt.filter}}
			if got := c.matchesFilter(tt.packet); got != tt.expected {
				t.Errorf("matchesFilter() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFilter_MatchesIP(t *testing.T) {
	tests := []struct {
		name     string
		filter   Filter
		packet   Packet
		expected bool
	}{
		{
			name:     "src IP filter matches",
			filter:   Filter{SrcHost: "192.168.1.1"},
			packet:   Packet{SrcIP: net.ParseIP("192.168.1.1")},
			expected: true,
		},
		{
			name:     "src IP filter rejects",
			filter:   Filter{SrcHost: "192.168.1.1"},
			packet:   Packet{SrcIP: net.ParseIP("192.168.1.2")},
			expected: false,
		},
		{
			name:     "dst IP filter matches",
			filter:   Filter{DstHost: "8.8.8.8"},
			packet:   Packet{DstIP: net.ParseIP("8.8.8.8")},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Capture{opts: CaptureOptions{Filter: tt.filter}}
			if got := c.matchesFilter(tt.packet); got != tt.expected {
				t.Errorf("matchesFilter() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPacket_Format(t *testing.T) {
	pkt := Packet{
		Timestamp: time.Date(2026, 1, 28, 12, 30, 45, 123000000, time.UTC),
		Protocol:  "TCP",
		SrcIP:     net.ParseIP("192.168.1.100"),
		SrcPort:   52341,
		DstIP:     net.ParseIP("8.8.8.8"),
		DstPort:   443,
		Length:    1500,
		Info:      "HTTPS",
	}

	formatted := pkt.Format()
	if formatted == "" {
		t.Error("Format() returned empty string")
	}

	// Check expected parts
	expectedParts := []string{"TCP", "192.168.1.100", "52341", "8.8.8.8", "443", "1500"}
	for _, part := range expectedParts {
		if !contains(formatted, part) {
			t.Errorf("Format() missing expected part: %s", part)
		}
	}
}

func TestStats_Format(t *testing.T) {
	stats := Stats{
		PacketsCaptured: 100,
		BytesCaptured:   150000,
		Duration:        5 * time.Second,
		ProtocolCounts: map[string]uint64{
			"TCP": 80,
			"UDP": 20,
		},
	}

	formatted := stats.Format()
	if formatted == "" {
		t.Error("Format() returned empty string")
	}

	expectedParts := []string{"100", "150000", "TCP", "UDP"}
	for _, part := range expectedParts {
		if !contains(formatted, part) {
			t.Errorf("Format() missing expected part: %s", part)
		}
	}
}

func TestCapture_RecordPacket(t *testing.T) {
	c := &Capture{
		opts: DefaultOptions(),
		stats: Stats{
			ProtocolCounts: make(map[string]uint64),
		},
	}

	pkt := Packet{
		Timestamp: time.Now(),
		Protocol:  "TCP",
		Length:    1500,
		SrcIP:     net.ParseIP("192.168.1.1"),
		DstIP:     net.ParseIP("8.8.8.8"),
		SrcPort:   52000,
		DstPort:   443,
	}

	c.recordPacket(pkt)

	if c.stats.PacketsCaptured != 1 {
		t.Errorf("expected 1 packet captured, got %d", c.stats.PacketsCaptured)
	}
	if c.stats.BytesCaptured != 1500 {
		t.Errorf("expected 1500 bytes, got %d", c.stats.BytesCaptured)
	}
	if c.stats.ProtocolCounts["TCP"] != 1 {
		t.Errorf("expected TCP count 1, got %d", c.stats.ProtocolCounts["TCP"])
	}
}

func TestCapture_Handler(t *testing.T) {
	c := &Capture{
		opts: DefaultOptions(),
		stats: Stats{
			ProtocolCounts: make(map[string]uint64),
		},
	}

	var handlerCalled bool
	var receivedPacket Packet

	c.SetHandler(func(pkt Packet) {
		handlerCalled = true
		receivedPacket = pkt
	})

	pkt := Packet{
		Protocol: "UDP",
		Length:   500,
	}

	c.recordPacket(pkt)

	if !handlerCalled {
		t.Error("handler was not called")
	}
	if receivedPacket.Protocol != "UDP" {
		t.Errorf("handler received wrong packet protocol: %s", receivedPacket.Protocol)
	}
}

func TestCapture_StartStop(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxDuration = 100 * time.Millisecond

	// Skip if no interfaces available
	ifaces, _ := net.Interfaces()
	if len(ifaces) == 0 {
		t.Skip("no network interfaces available")
	}

	// Find a valid interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			opts.Interface = iface.Name
			break
		}
	}

	if opts.Interface == "" {
		t.Skip("no suitable interface found")
	}

	c, err := NewCapture(opts)
	if err != nil {
		t.Fatalf("NewCapture failed: %v", err)
	}

	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !c.IsRunning() {
		t.Error("capture should be running")
	}

	time.Sleep(150 * time.Millisecond) // Wait for MaxDuration

	// Should auto-stop due to MaxDuration
	time.Sleep(50 * time.Millisecond)
	if c.IsRunning() {
		c.Stop()
	}
}

func TestListInterfaces(t *testing.T) {
	ifaces, err := ListInterfaces()
	if err != nil {
		t.Fatalf("ListInterfaces failed: %v", err)
	}

	// We can't guarantee interfaces exist, but the function should work
	t.Logf("Found %d interfaces", len(ifaces))
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
