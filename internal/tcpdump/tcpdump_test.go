package tcpdump

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ci := Analyze(context.Background(), "127.0.0.1", port, false, 5*time.Second)

	if !ci.Reachable {
		t.Errorf("expected reachable, got error: %s", ci.Error)
	}
	if ci.State != "established" {
		t.Errorf("expected established, got %s", ci.State)
	}
	if ci.LocalAddr == "" {
		t.Error("expected local addr")
	}
	if ci.RemoteAddr == "" {
		t.Error("expected remote addr")
	}
}

func TestAnalyzeRefused(t *testing.T) {
	ci := Analyze(context.Background(), "127.0.0.1", "1", false, time.Second)
	if ci.Reachable {
		t.Error("expected not reachable")
	}
	if ci.State != "refused" {
		t.Errorf("expected refused, got %s", ci.State)
	}
}

func TestAnalyzeWithTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)

	ci := Analyze(context.Background(), "127.0.0.1", port, true, 5*time.Second)
	if !ci.Reachable {
		t.Fatalf("expected reachable, got error: %s", ci.Error)
	}
	if !ci.TLSEnabled {
		t.Error("expected TLS enabled")
	}
	if ci.TLSVersion == "" {
		t.Error("expected TLS version")
	}
	if ci.TLSCipher == "" {
		t.Error("expected TLS cipher")
	}
	if ci.TLSTime <= 0 {
		t.Error("expected positive TLS time")
	}
}

func TestAnalyzeTiming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ci := Analyze(context.Background(), "127.0.0.1", port, false, 5*time.Second)

	if ci.DNSTime < 0 {
		t.Error("DNS time should be non-negative")
	}
	if ci.ConnectTime <= 0 {
		t.Error("connect time should be positive")
	}
	if ci.TotalTime <= 0 {
		t.Error("total time should be positive")
	}
}

func TestAnalyzeContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ci := Analyze(ctx, "192.0.2.1", "80", false, 5*time.Second)
	if ci.Reachable {
		t.Error("should not be reachable with cancelled context")
	}
}

func TestAnalyzeMulti(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, openPort, _ := net.SplitHostPort(ln.Addr().String())

	opts := Options{
		Host:    "127.0.0.1",
		Ports:   []string{openPort, "1"},
		Timeout: 2 * time.Second,
	}

	mr := AnalyzeMulti(context.Background(), opts)
	if mr.Open != 1 {
		t.Errorf("expected 1 open, got %d", mr.Open)
	}
	if mr.Closed != 1 {
		t.Errorf("expected 1 closed, got %d", mr.Closed)
	}
	if len(mr.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(mr.Results))
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions("example.com")
	if opts.Host != "example.com" {
		t.Errorf("unexpected host: %s", opts.Host)
	}
	if len(opts.Ports) != 1 || opts.Ports[0] != "80" {
		t.Error("expected default port 80")
	}
	if opts.TLS {
		t.Error("TLS should default to false")
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0000, "unknown (0x0000)"},
	}
	for _, tt := range tests {
		got := tlsVersionString(tt.v)
		if got != tt.want {
			t.Errorf("tlsVersionString(0x%04x) = %s, want %s", tt.v, got, tt.want)
		}
	}
}

func TestFormatConnInfoEstablished(t *testing.T) {
	ci := ConnInfo{
		Host:        "example.com",
		Port:        "443",
		State:       "established",
		IPVersion:   "IPv4",
		Address:     "93.184.216.34",
		LocalAddr:   "10.0.0.1:54321",
		RemoteAddr:  "93.184.216.34:443",
		DNSTime:     5 * time.Millisecond,
		ConnectTime: 20 * time.Millisecond,
		TotalTime:   25 * time.Millisecond,
		Reachable:   true,
	}
	out := FormatConnInfo(ci)
	if !strings.Contains(out, "established") {
		t.Error("should contain state")
	}
	if !strings.Contains(out, "IPv4") {
		t.Error("should contain IP version")
	}
	if !strings.Contains(out, "example.com") {
		t.Error("should contain host")
	}
}

func TestFormatConnInfoWithTLS(t *testing.T) {
	ci := ConnInfo{
		Host:        "example.com",
		Port:        "443",
		State:       "established",
		IPVersion:   "IPv4",
		Address:     "93.184.216.34",
		LocalAddr:   "10.0.0.1:54321",
		RemoteAddr:  "93.184.216.34:443",
		DNSTime:     5 * time.Millisecond,
		ConnectTime: 20 * time.Millisecond,
		TLSTime:     30 * time.Millisecond,
		TotalTime:   55 * time.Millisecond,
		TLSEnabled:  true,
		TLSVersion:  "TLS 1.3",
		TLSCipher:   "TLS_AES_128_GCM_SHA256",
		TLSALPN:     "h2",
		ServerName:  "example.com",
		Reachable:   true,
	}
	out := FormatConnInfo(ci)
	if !strings.Contains(out, "TLS 1.3") {
		t.Error("should contain TLS version")
	}
	if !strings.Contains(out, "TLS_AES_128_GCM_SHA256") {
		t.Error("should contain cipher")
	}
	if !strings.Contains(out, "h2") {
		t.Error("should contain ALPN")
	}
}

func TestFormatConnInfoError(t *testing.T) {
	ci := ConnInfo{
		Host:    "bad.host",
		Port:    "80",
		State:   "refused",
		Error:   "connection refused",
		DNSTime: time.Millisecond,
	}
	out := FormatConnInfo(ci)
	if !strings.Contains(out, "connection refused") {
		t.Error("should contain error")
	}
}

func TestFormatMultiResult(t *testing.T) {
	mr := MultiResult{
		Host: "example.com",
		Results: []ConnInfo{
			{Port: "80", State: "established", DNSTime: time.Millisecond, ConnectTime: 5 * time.Millisecond, Reachable: true},
			{Port: "443", State: "established", DNSTime: time.Millisecond, ConnectTime: 5 * time.Millisecond, TLSTime: 10 * time.Millisecond, TLSEnabled: true, TLSVersion: "TLS 1.3", Reachable: true},
			{Port: "22", State: "refused", Error: "refused"},
		},
		Open:   2,
		Closed: 1,
	}

	out := FormatMultiResult(mr)
	if !strings.Contains(out, "80") {
		t.Error("should contain port 80")
	}
	if !strings.Contains(out, "Open: 2") {
		t.Error("should contain open count")
	}
	if !strings.Contains(out, "Closed: 1") {
		t.Error("should contain closed count")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("should not truncate short strings")
	}
	r := truncate("a very long error message here", 10)
	if r != "a very lon..." {
		t.Errorf("unexpected truncation: %s", r)
	}
}

func TestAnalyzeIPv4Detection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ci := Analyze(context.Background(), "127.0.0.1", port, false, 5*time.Second)
	if ci.IPVersion != "IPv4" {
		t.Errorf("expected IPv4, got %s", ci.IPVersion)
	}
}

func TestAnalyzeProtocol(t *testing.T) {
	ci := Analyze(context.Background(), "127.0.0.1", "1", false, time.Second)
	if ci.Protocol != "tcp" {
		t.Errorf("expected tcp, got %s", ci.Protocol)
	}
}

func TestAnalyzeHost(t *testing.T) {
	ci := Analyze(context.Background(), "test-host", "80", false, time.Second)
	if ci.Host != "test-host" {
		t.Errorf("expected test-host, got %s", ci.Host)
	}
	if ci.Port != "80" {
		t.Errorf("expected 80, got %s", ci.Port)
	}
}

func TestFormatMultiResultEmpty(t *testing.T) {
	mr := MultiResult{Host: "test.com"}
	out := FormatMultiResult(mr)
	if !strings.Contains(out, "Port") {
		t.Error("should contain header")
	}
	_ = fmt.Sprintf("output: %s", out)
}
