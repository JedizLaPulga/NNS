package geoloc

import (
	"context"
	"testing"
	"time"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"208.67.222.222", false},
		{"172.15.0.1", false}, // Just below private range
		{"172.32.0.1", false}, // Just above private range
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := IsPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
	}
	if cfg.MaxParallel != 5 {
		t.Errorf("MaxParallel = %d, want 5", cfg.MaxParallel)
	}
	if !cfg.IncludeDNS {
		t.Error("IncludeDNS = false, want true")
	}
}

func TestNewClient(t *testing.T) {
	cfg := DefaultConfig()
	client := NewClient(cfg)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.cache == nil {
		t.Error("cache not initialized")
	}
	if client.httpClient == nil {
		t.Error("httpClient not initialized")
	}
}

func TestLookupPrivateIP(t *testing.T) {
	client := NewClient(DefaultConfig())
	ctx := context.Background()

	info, err := client.Lookup(ctx, "192.168.1.1")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if !info.IsPrivate {
		t.Error("IsPrivate = false, want true")
	}
	if info.Country != "Private" {
		t.Errorf("Country = %q, want 'Private'", info.Country)
	}
	if info.City != "Local Network" {
		t.Errorf("City = %q, want 'Local Network'", info.City)
	}
}

func TestCaching(t *testing.T) {
	client := NewClient(DefaultConfig())
	ctx := context.Background()

	// Lookup private IP twice
	_, err := client.Lookup(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("First lookup failed: %v", err)
	}

	// Second lookup should use cache
	start := time.Now()
	info, err := client.Lookup(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("Second lookup failed: %v", err)
	}

	if time.Since(start) > 10*time.Millisecond {
		t.Error("Cache lookup took too long, cache may not be working")
	}
	if !info.IsPrivate {
		t.Error("Cached result incorrect")
	}
}

func TestHaversine(t *testing.T) {
	// NYC to London is approximately 5570 km
	dist := Haversine(40.7128, -74.0060, 51.5074, -0.1278)

	// Allow 10% margin due to approximation
	if dist < 5000 || dist > 6000 {
		t.Errorf("Haversine(NYC, London) = %v km, want ~5570 km", dist)
	}
}

func TestGeoInfoFormatLocation(t *testing.T) {
	tests := []struct {
		name     string
		info     GeoInfo
		expected string
	}{
		{
			name:     "full location",
			info:     GeoInfo{City: "New York", Region: "NY", Country: "United States"},
			expected: "New York, NY, United States",
		},
		{
			name:     "city and country only",
			info:     GeoInfo{City: "London", Country: "United Kingdom"},
			expected: "London, United Kingdom",
		},
		{
			name:     "private network",
			info:     GeoInfo{IsPrivate: true},
			expected: "Private Network",
		},
		{
			name:     "empty",
			info:     GeoInfo{},
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.info.FormatLocation()
			if result != tt.expected {
				t.Errorf("FormatLocation() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestCountryFlag(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"US", "🇺🇸"},
		{"GB", "🇬🇧"},
		{"DE", "🇩🇪"},
		{"JP", "🇯🇵"},
		{"", "🌐"},
		{"X", "🌐"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			info := GeoInfo{CountryCode: tt.code}
			result := info.CountryFlag()
			if result != tt.expected {
				t.Errorf("CountryFlag(%q) = %q, want %q", tt.code, result, tt.expected)
			}
		})
	}
}

func TestLookupBatch(t *testing.T) {
	client := NewClient(DefaultConfig())
	ctx := context.Background()

	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}
	results := client.LookupBatch(ctx, ips)

	if len(results) != 3 {
		t.Errorf("LookupBatch returned %d results, want 3", len(results))
	}

	for _, ip := range ips {
		if info, ok := results[ip]; !ok {
			t.Errorf("Missing result for %s", ip)
		} else if !info.IsPrivate {
			t.Errorf("%s should be private", ip)
		}
	}
}

func TestSqrt(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
		delta    float64
	}{
		{4, 2, 0.01},
		{9, 3, 0.01},
		{2, 1.414, 0.01},
		{0, 0, 0.01},
	}

	for _, tt := range tests {
		result := sqrt(tt.input)
		if result < tt.expected-tt.delta || result > tt.expected+tt.delta {
			t.Errorf("sqrt(%v) = %v, want ~%v", tt.input, result, tt.expected)
		}
	}
}
