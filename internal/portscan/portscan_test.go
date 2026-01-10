package portscan

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{
			name:  "single port",
			input: "80",
			want:  []int{80},
		},
		{
			name:  "multiple ports",
			input: "80,443,8080",
			want:  []int{80, 443, 8080},
		},
		{
			name:  "port range",
			input: "8000-8003",
			want:  []int{8000, 8001, 8002, 8003},
		},
		{
			name:  "mixed ports and ranges",
			input: "22,80,443,8000-8002",
			want:  []int{22, 80, 443, 8000, 8001, 8002},
		},
		{
			name:  "with spaces",
			input: "80, 443, 8080",
			want:  []int{80, 443, 8080},
		},
		{
			name:  "duplicate ports",
			input: "80,80,443,80",
			want:  []int{80, 443},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid port number",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "port out of range",
			input:   "70000",
			wantErr: true,
		},
		{
			name:    "port zero",
			input:   "0",
			wantErr: true,
		},
		{
			name:    "invalid range",
			input:   "100-50",
			wantErr: true,
		},
		{
			name:    "malformed range",
			input:   "80-90-100",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortRange(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePortRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePortRange() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int // Number of hosts expected
		wantErr   bool
	}{
		{
			name:      "single IP",
			input:     "192.168.1.1",
			wantCount: 1,
		},
		{
			name:      "hostname",
			input:     "example.com",
			wantCount: 1,
		},
		{
			name:      "/30 subnet (2 hosts)",
			input:     "192.168.1.0/30",
			wantCount: 2, // .1 and .2 (excluding network .0 and broadcast .3)
		},
		{
			name:      "/24 subnet",
			input:     "192.168.1.0/24",
			wantCount: 254, // Excluding network and broadcast
		},
		{
			name:    "invalid CIDR",
			input:   "192.168.1.0/99",
			wantErr: true,
		},
		{
			name:    "invalid format",
			input:   "not-a-cidr/24",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCIDR(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantCount {
				t.Errorf("ParseCIDR() got %d hosts, want %d", len(got), tt.wantCount)
			}
		})
	}
}

func TestScanPort(t *testing.T) {
	// Start a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	testPort := listener.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("TEST BANNER\n"))
			conn.Close()
		}
	}()

	tests := []struct {
		name     string
		host     string
		port     int
		wantOpen bool
	}{
		{
			name:     "open port",
			host:     "127.0.0.1",
			port:     testPort,
			wantOpen: true,
		},
		{
			name:     "closed port",
			host:     "127.0.0.1",
			port:     9, // Discard port, unlikely to be open
			wantOpen: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScanPort(tt.host, tt.port, 2*time.Second, 1*time.Second)
			if result.Open != tt.wantOpen {
				t.Errorf("ScanPort() Open = %v, want %v", result.Open, tt.wantOpen)
			}
			if tt.wantOpen && result.Banner == "" {
				t.Log("Warning: Expected banner but got empty string")
			}
		})
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()

	if scanner.Timeout != 2*time.Second {
		t.Errorf("NewScanner() Timeout = %v, want %v", scanner.Timeout, 2*time.Second)
	}

	if scanner.Concurrency != 100 {
		t.Errorf("NewScanner() Concurrency = %v, want %v", scanner.Concurrency, 100)
	}
}

func TestScannerScanPorts(t *testing.T) {
	// Start multiple test servers
	var testPorts []int
	var listeners []net.Listener

	for i := 0; i < 3; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to start test server: %v", err)
		}
		defer listener.Close()
		listeners = append(listeners, listener)
		testPorts = append(testPorts, listener.Addr().(*net.TCPAddr).Port)

		// Accept connections
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}(listener)
	}

	scanner := NewScanner()
	scanner.Concurrency = 10

	// Scan the test ports plus some closed ports
	portsToScan := append(testPorts, 9, 10, 11)

	results := scanner.ScanPorts(context.Background(), "127.0.0.1", portsToScan)

	if len(results) != len(portsToScan) {
		t.Errorf("ScanPorts() returned %d results, want %d", len(results), len(portsToScan))
	}

	// Count open ports
	openCount := 0
	for _, result := range results {
		if result.Open {
			openCount++
		}
	}

	if openCount != len(testPorts) {
		t.Errorf("ScanPorts() found %d open ports, want %d", openCount, len(testPorts))
	}

	// Verify results are sorted by port
	for i := 1; i < len(results); i++ {
		if results[i-1].Port >= results[i].Port {
			t.Error("ScanPorts() results are not sorted by port number")
			break
		}
	}
}

func TestCommonPorts(t *testing.T) {
	ports := CommonPorts()

	if len(ports) == 0 {
		t.Error("CommonPorts() returned empty slice")
	}

	// Check for some expected common ports
	expectedPorts := map[int]bool{
		22:   true, // SSH
		80:   true, // HTTP
		443:  true, // HTTPS
		3306: true, // MySQL
	}

	for _, port := range ports {
		if expectedPorts[port] {
			delete(expectedPorts, port)
		}
	}

	if len(expectedPorts) > 0 {
		t.Errorf("CommonPorts() missing expected ports: %v", expectedPorts)
	}
}

func BenchmarkScanPort(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to start test server: %v", err)
	}
	defer listener.Close()

	testPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScanPort("127.0.0.1", testPort, 2*time.Second, 1*time.Second)
	}
}

func BenchmarkParsePortRange(b *testing.B) {
	input := "22,80,443,8000-8100,9000-9100"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParsePortRange(input)
	}
}
