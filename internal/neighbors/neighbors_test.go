package neighbors

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", opts.Timeout)
	}
	if len(opts.ServiceTypes) == 0 {
		t.Error("expected non-empty service types")
	}
}

func TestCommonServices(t *testing.T) {
	services := CommonServices()
	if len(services) == 0 {
		t.Fatal("expected non-empty common services list")
	}

	// Check that all types end with .local.
	for _, s := range services {
		if !strings.HasSuffix(s.Type, ".local.") {
			t.Errorf("service type %q should end with .local.", s.Type)
		}
		if s.Name == "" {
			t.Error("service name should not be empty")
		}
		if s.Description == "" {
			t.Error("service description should not be empty")
		}
	}
}

func TestNewScanner(t *testing.T) {
	s := NewScanner(Options{})
	if s.opts.Timeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", s.opts.Timeout)
	}
	if len(s.opts.ServiceTypes) == 0 {
		t.Error("expected default service types")
	}
	if s.neighbors == nil {
		t.Error("expected neighbors map to be initialized")
	}
}

func TestNewScannerCustom(t *testing.T) {
	s := NewScanner(Options{
		Timeout:      10 * time.Second,
		ServiceTypes: []string{"_http._tcp.local."},
	})
	if s.opts.Timeout != 10*time.Second {
		t.Errorf("expected 10s, got %v", s.opts.Timeout)
	}
	if len(s.opts.ServiceTypes) != 1 {
		t.Errorf("expected 1 service type, got %d", len(s.opts.ServiceTypes))
	}
}

func TestBuildMDNSQuery(t *testing.T) {
	query := buildMDNSQuery("_http._tcp.local.")

	// Minimum size: 12 (header) + encoded name + 4 (type+class)
	if len(query) < 12 {
		t.Fatalf("query too short: %d bytes", len(query))
	}

	// Check header
	// QDCOUNT should be 1
	qdcount := uint16(query[4])<<8 | uint16(query[5])
	if qdcount != 1 {
		t.Errorf("expected QDCOUNT=1, got %d", qdcount)
	}

	// ANCOUNT should be 0
	ancount := uint16(query[6])<<8 | uint16(query[7])
	if ancount != 0 {
		t.Errorf("expected ANCOUNT=0, got %d", ancount)
	}
}

func TestEncodeDNSName(t *testing.T) {
	tests := []struct {
		name string
		want int // expected byte length
	}{
		{"_http._tcp.local.", 18}, // 1+5(_http) + 1+4(_tcp) + 1+5(local) + 1(null) = 18
		{"a.b.", 5},               // 1+a + 1+b + 1(null)
		{"test", 6},               // 1+4(test) + 1(null)
	}

	for _, tt := range tests {
		encoded := encodeDNSName(tt.name)
		if len(encoded) != tt.want {
			t.Errorf("encodeDNSName(%q) = %d bytes, want %d", tt.name, len(encoded), tt.want)
		}
		// Should end with null byte
		if encoded[len(encoded)-1] != 0 {
			t.Errorf("encodeDNSName(%q) should end with null byte", tt.name)
		}
	}
}

func TestParseDNSMessageTooShort(t *testing.T) {
	_, err := parseDNSMessage([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for short message")
	}
}

func TestParseDNSMessageMinimal(t *testing.T) {
	// Construct a minimal response with header only, no questions or answers
	data := make([]byte, 12)
	data[2] = 0x84 // QR=1, AA=1 (response)
	data[3] = 0x00

	msg, err := parseDNSMessage(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.questions != 0 {
		t.Errorf("expected 0 questions, got %d", msg.questions)
	}
	if len(msg.answers) != 0 {
		t.Errorf("expected 0 answers, got %d", len(msg.answers))
	}
}

func TestParseDNSMessageWithAnswer(t *testing.T) {
	// Build a response with one A record answer
	var buf []byte

	// Header
	buf = append(buf, 0, 0)    // ID
	buf = append(buf, 0x84, 0) // Flags: QR=1, AA=1
	buf = append(buf, 0, 0)    // QDCOUNT=0
	buf = append(buf, 0, 1)    // ANCOUNT=1
	buf = append(buf, 0, 0)    // NSCOUNT=0
	buf = append(buf, 0, 0)    // ARCOUNT=0

	// Answer: test.local. A 192.168.1.100
	name := encodeDNSName("test.local.")
	buf = append(buf, name...)
	buf = append(buf, 0, 1)        // TYPE=A
	buf = append(buf, 0, 1)        // CLASS=IN
	buf = append(buf, 0, 0, 0, 60) // TTL=60
	buf = append(buf, 0, 4)        // RDLENGTH=4
	buf = append(buf, 192, 168, 1, 100)

	msg, err := parseDNSMessage(buf)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(msg.answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.answers))
	}

	ans := msg.answers[0]
	if ans.name != "test.local" {
		t.Errorf("expected name 'test.local', got %q", ans.name)
	}
	if ans.rrType != dnsTypeA {
		t.Errorf("expected type A (1), got %d", ans.rrType)
	}
	if ans.ttl != 60 {
		t.Errorf("expected TTL 60, got %d", ans.ttl)
	}

	ip := parseIPFromRData(ans.rdata, ans.rrType)
	if ip != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", ip)
	}
}

func TestParseIPFromRData(t *testing.T) {
	tests := []struct {
		rdata  []byte
		rrType uint16
		want   string
	}{
		{[]byte{10, 0, 0, 1}, dnsTypeA, "10.0.0.1"},
		{[]byte{192, 168, 1, 1}, dnsTypeA, "192.168.1.1"},
		{net.ParseIP("::1").To16(), dnsTypeAAAA, "::1"},
		{[]byte{1, 2, 3}, dnsTypeA, ""}, // wrong length
		{[]byte{1, 2}, dnsTypeAAAA, ""}, // wrong length
		{[]byte{1}, 99, ""},             // unknown type
	}

	for _, tt := range tests {
		got := parseIPFromRData(tt.rdata, tt.rrType)
		if got != tt.want {
			t.Errorf("parseIPFromRData(%v, %d) = %q, want %q", tt.rdata, tt.rrType, got, tt.want)
		}
	}
}

func TestParseTXTRecord(t *testing.T) {
	// Build TXT rdata: length-prefixed strings
	var rdata []byte
	rdata = append(rdata, 5)
	rdata = append(rdata, []byte("a=b c")...)
	rdata = append(rdata, 3)
	rdata = append(rdata, []byte("x=y")...)
	rdata = append(rdata, 4)
	rdata = append(rdata, []byte("flag")...)

	txt := parseTXTRecord(rdata)

	if txt["a"] != "b c" {
		t.Errorf("expected a='b c', got %q", txt["a"])
	}
	if txt["x"] != "y" {
		t.Errorf("expected x='y', got %q", txt["x"])
	}
	if _, ok := txt["flag"]; !ok {
		t.Error("expected 'flag' key to exist")
	}
}

func TestParseTXTRecordEmpty(t *testing.T) {
	txt := parseTXTRecord([]byte{})
	if len(txt) != 0 {
		t.Errorf("expected empty map, got %d entries", len(txt))
	}
}

func TestCleanDNSName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"test.local.", "test.local"},
		{"test.local", "test.local"},
		{"hostname.", "hostname"},
		{"", ""},
	}

	for _, tt := range tests {
		got := cleanDNSName(tt.input)
		if got != tt.want {
			t.Errorf("cleanDNSName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestContainsString(t *testing.T) {
	if !containsString([]string{"a", "b", "c"}, "b") {
		t.Error("should contain 'b'")
	}
	if containsString([]string{"a", "b"}, "c") {
		t.Error("should not contain 'c'")
	}
	if containsString(nil, "a") {
		t.Error("nil slice should not contain anything")
	}
}

func TestResultFormat(t *testing.T) {
	r := &Result{
		TotalHosts: 2,
		TotalSvcs:  1,
		Duration:   3 * time.Second,
		Neighbors: []Neighbor{
			{
				Hostname:  "printer",
				Addresses: []string{"192.168.1.50"},
				Source:    "mDNS",
				Services: []DiscoveredService{
					{ServiceType: "_ipp._tcp.local"},
				},
			},
			{
				Hostname:  "server",
				Addresses: []string{"192.168.1.10", "fe80::1"},
				Source:    "DNS-SD",
			},
		},
		Services: []DiscoveredService{
			{
				InstanceName: "My Printer",
				ServiceType:  "_ipp._tcp.local",
				Port:         631,
				Host:         "printer.local",
				TXT:          map[string]string{"rp": "ipp/print", "ty": "HP LaserJet"},
			},
		},
	}

	output := r.Format()

	if !strings.Contains(output, "NETWORK NEIGHBOR DISCOVERY") {
		t.Error("should contain header")
	}
	if !strings.Contains(output, "printer") {
		t.Error("should contain hostname")
	}
	if !strings.Contains(output, "192.168.1.50") {
		t.Error("should contain IP address")
	}
	if !strings.Contains(output, "My Printer") {
		t.Error("should contain service instance")
	}
	if !strings.Contains(output, "631") {
		t.Error("should contain port")
	}
	if !strings.Contains(output, "HP LaserJet") {
		t.Error("should contain TXT value")
	}
}

func TestResultFormatCompact(t *testing.T) {
	r := &Result{
		TotalHosts: 5,
		TotalSvcs:  3,
		Duration:   2 * time.Second,
	}

	compact := r.FormatCompact()
	if !strings.Contains(compact, "5 hosts") {
		t.Error("should contain host count")
	}
	if !strings.Contains(compact, "3 services") {
		t.Error("should contain service count")
	}
}

func TestResultFormatWithErrors(t *testing.T) {
	r := &Result{
		Duration: time.Second,
		Errors:   []string{"query failed: timeout"},
	}

	output := r.Format()
	if !strings.Contains(output, "query failed: timeout") {
		t.Error("should contain error")
	}
}

func TestProcessResponseARecord(t *testing.T) {
	s := NewScanner(Options{Timeout: time.Second})

	// Build a minimal mDNS response with an A record
	var buf []byte
	buf = append(buf, 0, 0)    // ID
	buf = append(buf, 0x84, 0) // Flags: QR=1, AA=1
	buf = append(buf, 0, 0)    // QDCOUNT=0
	buf = append(buf, 0, 1)    // ANCOUNT=1
	buf = append(buf, 0, 0)    // NSCOUNT=0
	buf = append(buf, 0, 0)    // ARCOUNT=0

	name := encodeDNSName("mydevice.local.")
	buf = append(buf, name...)
	buf = append(buf, 0, 1)         // TYPE=A
	buf = append(buf, 0, 1)         // CLASS=IN
	buf = append(buf, 0, 0, 0, 120) // TTL=120
	buf = append(buf, 0, 4)         // RDLENGTH=4
	buf = append(buf, 192, 168, 1, 42)

	from := &net.UDPAddr{IP: net.ParseIP("192.168.1.42"), Port: 5353}
	s.processResponse(buf, from)

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.neighbors) == 0 {
		t.Fatal("expected at least one neighbor")
	}

	// The name "mydevice.local" gets trimmed to "mydevice" by processResponse
	// but also the source IP "192.168.1.42" is registered
	found := false
	for key, n := range s.neighbors {
		_ = key
		for _, addr := range n.Addresses {
			if addr == "192.168.1.42" {
				found = true
			}
		}
	}
	if !found {
		t.Error("should have found neighbor with address 192.168.1.42")
	}
}

func TestNeighborFields(t *testing.T) {
	n := Neighbor{
		Hostname:  "test-host",
		Addresses: []string{"10.0.0.1"},
		Source:    "mDNS",
		FirstSeen: time.Now(),
		Services: []DiscoveredService{
			{InstanceName: "Test", ServiceType: "_http._tcp.local"},
		},
	}

	if n.Hostname != "test-host" {
		t.Errorf("expected test-host, got %s", n.Hostname)
	}
	if len(n.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(n.Services))
	}
}

func TestDecodeDNSNameLoop(t *testing.T) {
	// Create data with a compression loop
	data := []byte{0xC0, 0x00} // Points to itself
	_, _, err := decodeDNSName(data, 0)
	if err == nil {
		t.Error("expected error for loop")
	}
}
