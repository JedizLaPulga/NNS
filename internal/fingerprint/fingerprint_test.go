package fingerprint

import (
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", opts.Timeout)
	}
	if opts.Concurrency != 20 {
		t.Errorf("Concurrency = %d, want 20", opts.Concurrency)
	}
	if !opts.OSDetect {
		t.Error("OSDetect should be true")
	}
	if !opts.ServiceScan {
		t.Error("ServiceScan should be true")
	}
	if len(opts.Ports) == 0 {
		t.Error("Ports should not be empty")
	}
}

func TestNewScanner(t *testing.T) {
	s := NewScanner(DefaultOptions())
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestOSFamily(t *testing.T) {
	families := []OSFamily{OSLinux, OSWindows, OSBSD, OSDarwin, OSSolaris, OSUnknown}
	for _, f := range families {
		if f == "" {
			t.Error("OSFamily should not be empty")
		}
	}
}

func TestConfidence(t *testing.T) {
	levels := []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow}
	for _, c := range levels {
		if c == "" {
			t.Error("Confidence should not be empty")
		}
	}
}

func TestKnownOSSignatures(t *testing.T) {
	if len(KnownOSSignatures) < 5 {
		t.Errorf("expected at least 5 signatures, got %d", len(KnownOSSignatures))
	}

	// Check all have required fields
	for _, sig := range KnownOSSignatures {
		if sig.Family == "" {
			t.Error("signature Family should not be empty")
		}
		if sig.TTL == 0 {
			t.Error("signature TTL should not be zero")
		}
	}
}

func TestCommonPorts(t *testing.T) {
	if len(CommonPorts) == 0 {
		t.Error("CommonPorts should not be empty")
	}

	// Should include standard ports
	has22 := false
	has80 := false
	has443 := false
	for _, p := range CommonPorts {
		if p == 22 {
			has22 = true
		}
		if p == 80 {
			has80 = true
		}
		if p == 443 {
			has443 = true
		}
	}
	if !has22 || !has80 || !has443 {
		t.Error("CommonPorts should include 22, 80, 443")
	}
}

func TestGuessTTLOrigin(t *testing.T) {
	s := NewScanner(DefaultOptions())

	tests := []struct {
		ttl      int
		contains string
	}{
		{64, "Linux"},
		{60, "Linux"},
		{128, "Windows"},
		{120, "Windows"},
		{255, "Solaris"},
	}

	for _, tt := range tests {
		result := s.guessTTLOrigin(tt.ttl)
		if !containsStr(result, tt.contains) {
			t.Errorf("guessTTLOrigin(%d) = %s, should contain %s", tt.ttl, result, tt.contains)
		}
	}
}

func TestEstimateDistance(t *testing.T) {
	s := NewScanner(DefaultOptions())

	tests := []struct {
		ttl      int
		expected int
	}{
		{64, 0},  // Origin
		{60, 4},  // 4 hops from 64
		{128, 0}, // Origin
		{120, 8}, // 8 hops from 128
	}

	for _, tt := range tests {
		result := s.estimateDistance(tt.ttl)
		if result != tt.expected {
			t.Errorf("estimateDistance(%d) = %d, want %d", tt.ttl, result, tt.expected)
		}
	}
}

func TestIdentifyService(t *testing.T) {
	s := NewScanner(DefaultOptions())

	tests := []struct {
		port    int
		banner  string
		service string
		product string
	}{
		{22, "SSH-2.0-OpenSSH_8.4", "ssh", "OpenSSH"},
		{80, "", "http", ""},
		{443, "", "https", ""},
		{22, "SSH-2.0-OpenSSH_7.9", "ssh", "OpenSSH"},
		{80, "nginx/1.18.0", "http", "nginx"},
	}

	for _, tt := range tests {
		service, product, _ := s.identifyService(tt.port, tt.banner)
		if service != tt.service {
			t.Errorf("identifyService(%d) service = %s, want %s", tt.port, service, tt.service)
		}
		if product != tt.product {
			t.Errorf("identifyService(%d) product = %s, want %s", tt.port, product, tt.product)
		}
	}
}

func TestAbs(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{5, 5},
		{-5, 5},
		{0, 0},
		{-100, 100},
	}

	for _, tt := range tests {
		result := abs(tt.input)
		if result != tt.expected {
			t.Errorf("abs(%d) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestGetPortsByState(t *testing.T) {
	result := &FingerprintResult{
		OpenPorts:     []int{22, 80},
		ClosedPorts:   []int{23},
		FilteredPorts: []int{8080},
	}

	ports := result.GetPortsByState()

	if len(ports["open"]) != 2 {
		t.Error("should have 2 open ports")
	}
	if len(ports["closed"]) != 1 {
		t.Error("should have 1 closed port")
	}
	if len(ports["filtered"]) != 1 {
		t.Error("should have 1 filtered port")
	}
}

func TestFormat(t *testing.T) {
	result := &FingerprintResult{
		Host:         "example.com",
		OSFamily:     OSLinux,
		OSVersion:    "Linux 5.x",
		OSConfidence: ConfidenceHigh,
		TTL:          64,
		TTLGuess:     "64 (Linux/macOS/BSD)",
		OpenPorts:    []int{22, 80},
		Duration:     100 * time.Millisecond,
	}

	output := result.Format()
	if len(output) == 0 {
		t.Error("Format returned empty string")
	}
	if !containsStr(output, "example.com") {
		t.Error("should contain host")
	}
	if !containsStr(output, "Linux") {
		t.Error("should contain OS family")
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFingerprintOS(t *testing.T) {
	s := NewScanner(DefaultOptions())
	result := &FingerprintResult{
		TTL:        64,
		WindowSize: 65535,
		Probes: []ProbeResult{
			{Responded: true, SACK: true},
		},
	}

	s.fingerprintOS(result)

	// Should match Linux or macOS (TTL 64)
	if result.OSFamily != OSLinux && result.OSFamily != OSDarwin && result.OSFamily != OSBSD {
		t.Errorf("OSFamily = %s, expected Linux/Darwin/BSD for TTL 64", result.OSFamily)
	}
}

func TestTCPFlags(t *testing.T) {
	flags := TCPFlags{
		SYN: true,
		ACK: true,
	}

	if !flags.SYN || !flags.ACK {
		t.Error("SYN/ACK should be set")
	}
	if flags.RST || flags.FIN {
		t.Error("RST/FIN should not be set")
	}
}
