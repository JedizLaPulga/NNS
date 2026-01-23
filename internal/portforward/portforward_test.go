package portforward

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				LocalAddr:  "127.0.0.1:0",
				RemoteAddr: "example.com:80",
			},
			wantErr: false,
		},
		{
			name: "missing local addr",
			cfg: Config{
				RemoteAddr: "example.com:80",
			},
			wantErr: true,
		},
		{
			name: "missing remote addr",
			cfg: Config{
				LocalAddr: "127.0.0.1:0",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, err := New(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && fwd == nil {
				t.Error("New() returned nil forwarder")
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LocalAddr != "127.0.0.1:8080" {
		t.Errorf("DefaultConfig().LocalAddr = %q, want 127.0.0.1:8080", cfg.LocalAddr)
	}
	if cfg.DialTimeout != 10*time.Second {
		t.Errorf("DefaultConfig().DialTimeout = %v, want 10s", cfg.DialTimeout)
	}
	if cfg.BufferSize != 32*1024 {
		t.Errorf("DefaultConfig().BufferSize = %d, want 32768", cfg.BufferSize)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{1048576, "1.00 MB"},
		{1073741824, "1.00 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := FormatBytes(tt.bytes)
			if got != tt.expected {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.bytes, got, tt.expected)
			}
		})
	}
}

func TestFormatStats(t *testing.T) {
	s := Stats{
		ActiveConns:   2,
		TotalConns:    100,
		BytesSent:     1048576,
		BytesReceived: 2097152,
		Errors:        5,
	}

	formatted := FormatStats(s)

	if !strings.Contains(formatted, "Active Connections: 2") {
		t.Error("FormatStats should contain active connections")
	}
	if !strings.Contains(formatted, "Total Connections:  100") {
		t.Error("FormatStats should contain total connections")
	}
	if !strings.Contains(formatted, "1.00 MB") {
		t.Error("FormatStats should contain formatted bytes sent")
	}
	if !strings.Contains(formatted, "Errors:             5") {
		t.Error("FormatStats should contain errors")
	}
}

func TestForwarder_StartStop(t *testing.T) {
	// Create a mock remote server
	remoteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create remote listener: %v", err)
	}
	defer remoteLn.Close()

	remoteAddr := remoteLn.Addr().String()

	// Handle remote connections
	go func() {
		for {
			conn, err := remoteLn.Accept()
			if err != nil {
				return
			}
			io.Copy(conn, conn) // Echo server
			conn.Close()
		}
	}()

	cfg := Config{
		LocalAddr:   "127.0.0.1:0",
		RemoteAddr:  remoteAddr,
		DialTimeout: 5 * time.Second,
	}

	fwd, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start forwarder in background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fwd.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(100 * time.Millisecond)

	// Stop the forwarder
	err = fwd.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	cancel()
	wg.Wait()
}

func TestForwarder_ForwardData(t *testing.T) {
	// Create a mock remote server that echoes data
	remoteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create remote listener: %v", err)
	}
	defer remoteLn.Close()

	remoteAddr := remoteLn.Addr().String()

	// Echo server
	go func() {
		conn, err := remoteLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	cfg := Config{
		LocalAddr:   "127.0.0.1:0",
		RemoteAddr:  remoteAddr,
		DialTimeout: 5 * time.Second,
	}

	fwd, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	connectCalled := false
	fwd.OnConnect(func(clientAddr, remoteAddr string) {
		connectCalled = true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start forwarder
	go fwd.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Get actual listen address
	localAddr := fwd.LocalAddr()

	// Connect through the forwarder
	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		t.Fatalf("Failed to connect to forwarder: %v", err)
	}
	defer conn.Close()

	// Send data
	testData := "Hello, forwarder!"
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	// Read echoed data
	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}

	if string(buf[:n]) != testData {
		t.Errorf("Echoed data = %q, want %q", string(buf[:n]), testData)
	}

	conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Check stats
	stats := fwd.Stats()
	if stats.TotalConns < 1 {
		t.Errorf("Stats.TotalConns = %d, want >= 1", stats.TotalConns)
	}

	if !connectCalled {
		t.Error("OnConnect callback was not called")
	}

	fwd.Stop()
}

func TestForwarder_Stats(t *testing.T) {
	cfg := Config{
		LocalAddr:  "127.0.0.1:0",
		RemoteAddr: "example.com:80",
	}

	fwd, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	stats := fwd.Stats()

	if stats.ActiveConns != 0 {
		t.Errorf("Initial Stats.ActiveConns = %d, want 0", stats.ActiveConns)
	}
	if stats.TotalConns != 0 {
		t.Errorf("Initial Stats.TotalConns = %d, want 0", stats.TotalConns)
	}
}

func TestForwarder_LocalAddr(t *testing.T) {
	cfg := Config{
		LocalAddr:  "127.0.0.1:0",
		RemoteAddr: "example.com:80",
	}

	fwd, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Before starting, should return config addr
	if fwd.LocalAddr() != cfg.LocalAddr {
		t.Errorf("LocalAddr() before start = %q, want %q", fwd.LocalAddr(), cfg.LocalAddr)
	}
}
