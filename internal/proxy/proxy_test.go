package proxy

import (
	"testing"
)

func TestNewProxy(t *testing.T) {
	cfg := Config{
		Port:    8080,
		Verbose: true,
		Filter:  "example.com",
	}

	p := NewProxy(cfg)

	if p == nil {
		t.Fatal("NewProxy should not return nil")
	}

	if p.cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", p.cfg.Port)
	}

	if !p.cfg.Verbose {
		t.Error("Verbose should be true")
	}

	if p.cfg.Filter != "example.com" {
		t.Errorf("Filter = %q, want 'example.com'", p.cfg.Filter)
	}

	if p.client == nil {
		t.Error("Client should not be nil")
	}
}

func TestShouldLog(t *testing.T) {
	tests := []struct {
		filter string
		target string
		want   bool
	}{
		{"", "anything", true}, // No filter = log everything
		{"example.com", "example.com", true},
		{"example.com", "https://example.com/path", true},
		{"example.com", "google.com", false},
		{"api", "https://api.example.com", true},
	}

	for _, tt := range tests {
		cfg := Config{Filter: tt.filter}
		p := NewProxy(cfg)

		got := p.shouldLog(tt.target)
		if got != tt.want {
			t.Errorf("shouldLog(%q) with filter %q = %v, want %v",
				tt.target, tt.filter, got, tt.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{2048, "2.0 KB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestConfig(t *testing.T) {
	cfg := Config{}

	// Test defaults
	if cfg.Port != 0 {
		t.Error("Default port should be 0")
	}
	if cfg.Verbose {
		t.Error("Default verbose should be false")
	}
	if cfg.Filter != "" {
		t.Error("Default filter should be empty")
	}
}
