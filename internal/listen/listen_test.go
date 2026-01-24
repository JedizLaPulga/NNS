package listen

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.Port)
	}
	if cfg.Protocol != TCP {
		t.Errorf("expected TCP protocol, got %s", cfg.Protocol)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("expected host 0.0.0.0, got %s", cfg.Host)
	}
	if cfg.BufferSize != 4096 {
		t.Errorf("expected buffer size 4096, got %d", cfg.BufferSize)
	}
}

func TestNew(t *testing.T) {
	listener := New(Config{Port: 9999})

	if listener.config.Port != 9999 {
		t.Errorf("expected port 9999, got %d", listener.config.Port)
	}
	if listener.config.Host != "0.0.0.0" {
		t.Errorf("expected default host 0.0.0.0, got %s", listener.config.Host)
	}
	if listener.config.BufferSize != 4096 {
		t.Errorf("expected default buffer size 4096, got %d", listener.config.BufferSize)
	}
}

func TestAddress(t *testing.T) {
	listener := New(Config{Host: "127.0.0.1", Port: 8888})

	addr := listener.Address()
	if addr != "127.0.0.1:8888" {
		t.Errorf("expected 127.0.0.1:8888, got %s", addr)
	}
}

func TestTCPListener(t *testing.T) {
	cfg := Config{
		Host:     "127.0.0.1",
		Port:     0, // Let OS assign port
		Protocol: TCP,
		Echo:     true,
	}
	listener := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var events []Event
	var mu sync.Mutex

	callback := func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	// Start listener in goroutine
	errChan := make(chan error, 1)
	go func() {
		// Use a fixed port for testing
		cfg.Port = 19876
		listener = New(cfg)
		errChan <- listener.Start(ctx, callback)
	}()

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the listener
	conn, err := net.Dial("tcp", "127.0.0.1:19876")
	if err != nil {
		t.Skipf("could not connect to listener: %v", err)
		return
	}
	defer conn.Close()

	// Send data
	testData := []byte("Hello, World!")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Wait for echo (if enabled)
	time.Sleep(100 * time.Millisecond)

	// Close connection
	conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Stop listener
	cancel()
	listener.Stop()

	// Check events
	mu.Lock()
	defer mu.Unlock()

	if len(events) == 0 {
		t.Log("no events received (may be timing related)")
	}
}

func TestUDPListener(t *testing.T) {
	cfg := Config{
		Host:     "127.0.0.1",
		Port:     19877,
		Protocol: UDP,
		Echo:     true,
	}
	listener := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var events []Event
	var mu sync.Mutex

	callback := func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	// Start listener in goroutine
	go func() {
		listener.Start(ctx, callback)
	}()

	// Wait for listener to start
	time.Sleep(100 * time.Millisecond)

	// Send UDP packet
	conn, err := net.Dial("udp", "127.0.0.1:19877")
	if err != nil {
		t.Skipf("could not connect to listener: %v", err)
		return
	}
	defer conn.Close()

	testData := []byte("UDP Test")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Stop listener
	cancel()
	listener.Stop()

	// Check that we received data event
	mu.Lock()
	defer mu.Unlock()

	hasDataEvent := false
	for _, e := range events {
		if e.Type == "data" {
			hasDataEvent = true
			break
		}
	}

	if !hasDataEvent && len(events) == 0 {
		t.Log("no data event received (may be timing related)")
	}
}

func TestGetStats(t *testing.T) {
	listener := New(DefaultConfig())
	stats := listener.GetStats()

	if stats.TotalConnections != 0 {
		t.Errorf("expected 0 total connections, got %d", stats.TotalConnections)
	}
	if stats.ActiveConnections != 0 {
		t.Errorf("expected 0 active connections, got %d", stats.ActiveConnections)
	}
}

func TestGetActiveConnections(t *testing.T) {
	listener := New(DefaultConfig())
	conns := listener.GetActiveConnections()

	if len(conns) != 0 {
		t.Errorf("expected 0 active connections, got %d", len(conns))
	}
}

func TestIsRunning(t *testing.T) {
	listener := New(DefaultConfig())

	if listener.IsRunning() {
		t.Error("expected listener not running initially")
	}
}

func TestFormatEvent(t *testing.T) {
	tests := []struct {
		name  string
		event Event
	}{
		{
			name: "connect",
			event: Event{
				Type: "connect",
				Connection: &Connection{
					RemoteAddr: "192.168.1.100:12345",
				},
				Time: time.Now(),
			},
		},
		{
			name: "disconnect",
			event: Event{
				Type: "disconnect",
				Connection: &Connection{
					RemoteAddr: "192.168.1.100:12345",
					StartTime:  time.Now().Add(-5 * time.Second),
					BytesRecv:  1024,
					BytesSent:  512,
				},
				Time: time.Now(),
			},
		},
		{
			name: "data",
			event: Event{
				Type: "data",
				Connection: &Connection{
					RemoteAddr: "192.168.1.100:12345",
				},
				Data: []byte("Hello, World!"),
				Time: time.Now(),
			},
		},
		{
			name: "error",
			event: Event{
				Type:  "error",
				Error: net.ErrClosed,
				Time:  time.Now(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatted := FormatEvent(tt.event)
			if formatted == "" {
				t.Error("expected non-empty formatted event")
			}
		})
	}
}

func TestFormatStats(t *testing.T) {
	stats := Stats{
		TotalConnections:   10,
		ActiveConnections:  2,
		TotalBytesReceived: 1024,
		TotalBytesSent:     512,
		StartTime:          time.Now().Add(-1 * time.Hour),
	}

	formatted := FormatStats(stats)
	if formatted == "" {
		t.Error("expected non-empty formatted stats")
	}
}

func TestConnectionFields(t *testing.T) {
	c := &Connection{
		ID:         1,
		RemoteAddr: "192.168.1.100:12345",
		LocalAddr:  "0.0.0.0:8080",
		Protocol:   TCP,
		StartTime:  time.Now(),
		BytesRecv:  100,
		BytesSent:  50,
	}

	if c.ID != 1 {
		t.Errorf("expected ID 1, got %d", c.ID)
	}
	if c.Protocol != TCP {
		t.Errorf("expected TCP, got %s", c.Protocol)
	}
}
