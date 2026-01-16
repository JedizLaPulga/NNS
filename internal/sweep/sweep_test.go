package sweep

import (
	"context"
	"testing"
	"time"
)

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "single IP",
			cidr:      "192.168.1.1",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "/30 subnet",
			cidr:      "192.168.1.0/30",
			wantCount: 2, // Excludes network and broadcast
			wantErr:   false,
		},
		{
			name:      "/24 subnet",
			cidr:      "192.168.1.0/24",
			wantCount: 254, // Excludes .0 and .255
			wantErr:   false,
		},
		{
			name:      "invalid CIDR",
			cidr:      "invalid",
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := ParseCIDR(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(hosts) != tt.wantCount {
				t.Errorf("ParseCIDR() returned %d hosts, want %d", len(hosts), tt.wantCount)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 1*time.Second {
		t.Errorf("DefaultConfig().Timeout = %v, want 1s", cfg.Timeout)
	}
	if cfg.Concurrency != 256 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 256", cfg.Concurrency)
	}
	if cfg.Method != "tcp" {
		t.Errorf("DefaultConfig().Method = %s, want tcp", cfg.Method)
	}
	if len(cfg.Ports) == 0 {
		t.Error("DefaultConfig().Ports should not be empty")
	}
}

func TestNewSweeper(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CIDR = "192.168.1.0/24"

	sweeper := NewSweeper(cfg)

	if sweeper.Config.CIDR != cfg.CIDR {
		t.Errorf("NewSweeper().Config.CIDR = %s, want %s", sweeper.Config.CIDR, cfg.CIDR)
	}
}

func TestSweepLocalhost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CIDR = "127.0.0.1"
	cfg.Ports = []int{80, 443, 22} // Common ports
	cfg.Timeout = 100 * time.Millisecond
	cfg.Resolve = false

	sweeper := NewSweeper(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := sweeper.Sweep(ctx, nil)
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Sweep() returned %d results, want 1", len(results))
	}

	// Localhost should return result (alive depends on if services are running)
	if results[0].IP != "127.0.0.1" {
		t.Errorf("Sweep() result IP = %s, want 127.0.0.1", results[0].IP)
	}
}

func TestCompareIPs(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"192.168.1.1", "192.168.1.2", -1},
		{"192.168.1.2", "192.168.1.1", 1},
		{"192.168.1.1", "192.168.1.1", 0},
		{"10.0.0.1", "192.168.1.1", -1},
	}

	for _, tt := range tests {
		got := compareIPs(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareIPs(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestGetAliveHosts(t *testing.T) {
	results := []HostResult{
		{IP: "192.168.1.1", Alive: true},
		{IP: "192.168.1.2", Alive: false},
		{IP: "192.168.1.3", Alive: true},
		{IP: "192.168.1.4", Alive: false},
	}

	alive := GetAliveHosts(results)

	if len(alive) != 2 {
		t.Errorf("GetAliveHosts() returned %d hosts, want 2", len(alive))
	}

	for _, h := range alive {
		if !h.Alive {
			t.Errorf("GetAliveHosts() returned dead host: %s", h.IP)
		}
	}
}

func TestCountHosts(t *testing.T) {
	count, err := CountHosts("192.168.1.0/24")
	if err != nil {
		t.Fatalf("CountHosts() error = %v", err)
	}
	if count != 254 {
		t.Errorf("CountHosts() = %d, want 254", count)
	}
}

func TestSweepWithCallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CIDR = "127.0.0.1"
	cfg.Timeout = 100 * time.Millisecond
	cfg.Resolve = false

	sweeper := NewSweeper(cfg)

	var callbackCalled bool
	callback := func(result HostResult) {
		callbackCalled = true
	}

	ctx := context.Background()
	_, err := sweeper.Sweep(ctx, callback)
	if err != nil {
		t.Fatalf("Sweep() error = %v", err)
	}

	// Callback is only called for alive hosts, so this depends on services
	t.Logf("Callback called: %v", callbackCalled)
}

func TestSweepContextCancellation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CIDR = "192.168.1.0/24"
	cfg.Timeout = 1 * time.Second

	sweeper := NewSweeper(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := sweeper.Sweep(ctx, nil)
	// Should not error, just return empty or partial results
	if err != nil {
		t.Logf("Sweep() with cancelled context: %v", err)
	}
}
