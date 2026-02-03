package netspeed

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != DefaultPort {
		t.Errorf("DefaultConfig().Port = %d, want %d", cfg.Port, DefaultPort)
	}
	if cfg.Duration != DefaultDuration {
		t.Errorf("DefaultConfig().Duration = %v, want %v", cfg.Duration, DefaultDuration)
	}
	if cfg.BufferSize != BufferSize {
		t.Errorf("DefaultConfig().BufferSize = %d, want %d", cfg.BufferSize, BufferSize)
	}
}

func TestNewServer(t *testing.T) {
	server := NewServer(Config{})

	if server.config.Port != DefaultPort {
		t.Errorf("NewServer().config.Port = %d, want %d", server.config.Port, DefaultPort)
	}
	if server.done == nil {
		t.Error("NewServer() should initialize done channel")
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient(Config{})

	if client.config.Duration != DefaultDuration {
		t.Errorf("NewClient().config.Duration = %v, want %v", client.config.Duration, DefaultDuration)
	}
	if client.config.Connections != 1 {
		t.Errorf("NewClient().config.Connections = %d, want 1", client.config.Connections)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.00 KB"},
		{1024 * 1024, "1.00 MB"},
		{1024 * 1024 * 1024, "1.00 GB"},
	}

	for _, tt := range tests {
		result := formatBytes(tt.bytes)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
		}
	}
}

func TestResultFormat(t *testing.T) {
	result := &Result{
		Role:        RoleClient,
		RemoteAddr:  "192.168.1.1:5201",
		LocalAddr:   "192.168.1.100:54321",
		Duration:    5 * time.Second,
		BytesSent:   100 * 1024 * 1024,
		SendSpeed:   160.0,
		Connections: 1,
	}

	output := result.Format()

	if output == "" {
		t.Error("Format() returned empty string")
	}
	if !strings.Contains(output, "160.00 Mbps") {
		t.Error("Format() should contain speed")
	}
	if !strings.Contains(output, "192.168.1.1:5201") {
		t.Error("Format() should contain remote address")
	}
}

func TestBandwidthMonitor(t *testing.T) {
	monitor := NewBandwidthMonitor()

	if monitor.startTime.IsZero() {
		t.Error("NewBandwidthMonitor should set start time")
	}

	sent, recv, elapsed := monitor.GetStats()
	if sent != 0 || recv != 0 {
		t.Error("Initial stats should be zero")
	}
	if elapsed < 0 {
		t.Error("Elapsed should be non-negative")
	}
}

func TestMonitoredReader(t *testing.T) {
	monitor := NewBandwidthMonitor()
	data := []byte("test data for reading")
	reader := monitor.WrapReader(bytes.NewReader(data))

	buf := make([]byte, 100)
	n, err := reader.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("Read error: %v", err)
	}

	if n != len(data) {
		t.Errorf("Read %d bytes, want %d", n, len(data))
	}

	_, recv, _ := monitor.GetStats()
	if recv != int64(len(data)) {
		t.Errorf("Monitor received = %d, want %d", recv, len(data))
	}
}

func TestMonitoredWriter(t *testing.T) {
	monitor := NewBandwidthMonitor()
	var buf bytes.Buffer
	writer := monitor.WrapWriter(&buf)

	data := []byte("test data for writing")
	n, err := writer.Write(data)
	if err != nil {
		t.Errorf("Write error: %v", err)
	}

	if n != len(data) {
		t.Errorf("Wrote %d bytes, want %d", n, len(data))
	}

	sent, _, _ := monitor.GetStats()
	if sent != int64(len(data)) {
		t.Errorf("Monitor sent = %d, want %d", sent, len(data))
	}
}

func TestServerStartStop(t *testing.T) {
	server := NewServer(Config{Port: 0}) // Use random port

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("Server.Start error: %v", err)
	}

	addr := server.Address()
	if addr == "" {
		t.Error("Server.Address should return address after Start")
	}

	stats := server.GetStats()
	if stats.StartTime.IsZero() {
		t.Error("Server stats should have start time")
	}

	server.Stop()
}

func TestServerClientIntegration(t *testing.T) {
	// Start server
	server := NewServer(Config{Port: 0})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("Server.Start error: %v", err)
	}
	defer server.Stop()

	addr := server.Address()

	// Run client test
	client := NewClient(Config{
		Duration:    1 * time.Second,
		Connections: 1,
	})

	result, err := client.Test(ctx, addr)
	if err != nil {
		t.Fatalf("Client.Test error: %v", err)
	}

	if result.BytesSent == 0 {
		t.Error("Client should have sent some bytes")
	}
	if result.SendSpeed == 0 {
		t.Error("Client should have calculated send speed")
	}
}

func TestRoleConstants(t *testing.T) {
	if RoleServer != "server" {
		t.Errorf("RoleServer = %s, want server", RoleServer)
	}
	if RoleClient != "client" {
		t.Errorf("RoleClient = %s, want client", RoleClient)
	}
}

func TestAtomicOperations(t *testing.T) {
	var counter int64

	atomic.AddInt64(&counter, 10)
	atomic.AddInt64(&counter, 20)

	if atomic.LoadInt64(&counter) != 30 {
		t.Errorf("Atomic counter = %d, want 30", counter)
	}
}
