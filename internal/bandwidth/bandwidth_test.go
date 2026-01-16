package bandwidth

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != 5201 {
		t.Errorf("Port = %d, want 5201", cfg.Port)
	}
	if cfg.BufferSize != 128*1024 {
		t.Errorf("BufferSize = %d, want %d", cfg.BufferSize, 128*1024)
	}
}

func TestFormatSpeed(t *testing.T) {
	tests := []struct {
		mbps float64
		want string
	}{
		{10.5, "10.50 Mbps"},
		{100.0, "100.00 Mbps"},
		{1000.0, "1.00 Gbps"},
		{2500.0, "2.50 Gbps"},
	}

	for _, tt := range tests {
		got := FormatSpeed(tt.mbps)
		if got != tt.want {
			t.Errorf("FormatSpeed(%f) = %q, want %q", tt.mbps, got, tt.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.00 KB"},
		{1024 * 1024, "1.00 MB"},
		{1024 * 1024 * 1024, "1.00 GB"},
		{1536 * 1024, "1.50 MB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestNewServer(t *testing.T) {
	server := NewServer(5201)
	if server.Port != 5201 {
		t.Errorf("Port = %d, want 5201", server.Port)
	}
}

func TestNewClient(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Target = "localhost"

	client := NewClient(cfg)
	if client.Config.Target != "localhost" {
		t.Errorf("Target = %q, want 'localhost'", client.Config.Target)
	}
}

func TestResultFields(t *testing.T) {
	result := &Result{
		Direction:     "download",
		BytesReceived: 1024 * 1024,
		DownloadSpeed: 100.0,
	}

	if result.Direction != "download" {
		t.Error("Direction field not set correctly")
	}
	if result.BytesReceived != 1024*1024 {
		t.Error("BytesReceived field not set correctly")
	}
	if result.DownloadSpeed != 100.0 {
		t.Error("DownloadSpeed field not set correctly")
	}
}
