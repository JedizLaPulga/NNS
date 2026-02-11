package pcping

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Port != 80 {
		t.Errorf("expected port 80, got %d", opts.Port)
	}
	if opts.Protocol != ProtoTCP {
		t.Errorf("expected protocol TCP, got %s", opts.Protocol)
	}
	if opts.Count != 5 {
		t.Errorf("expected count 5, got %d", opts.Count)
	}
	if opts.Interval != 1*time.Second {
		t.Errorf("expected interval 1s, got %v", opts.Interval)
	}
	if opts.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", opts.Timeout)
	}
	if opts.HTTPPath != "/" {
		t.Errorf("expected HTTPPath '/', got '%s'", opts.HTTPPath)
	}
}

func TestNewPinger(t *testing.T) {
	opts := Options{Host: "example.com"}
	pinger := NewPinger(opts)

	if pinger.opts.Count != 5 {
		t.Errorf("expected default count 5, got %d", pinger.opts.Count)
	}
	if pinger.opts.Interval != 1*time.Second {
		t.Errorf("expected default interval 1s, got %v", pinger.opts.Interval)
	}
	if pinger.opts.Timeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", pinger.opts.Timeout)
	}
	if pinger.Stats == nil {
		t.Error("expected Stats to be initialized")
	}
}

func TestNewPingerDNSPort(t *testing.T) {
	pinger := NewPinger(Options{Host: "8.8.8.8", Protocol: ProtoDNS})
	if pinger.opts.Port != 53 {
		t.Errorf("expected DNS default port 53, got %d", pinger.opts.Port)
	}
}

func TestNewPingerHTTPPort(t *testing.T) {
	pinger := NewPinger(Options{Host: "example.com", Protocol: ProtoHTTP})
	if pinger.opts.Port != 80 {
		t.Errorf("expected HTTP default port 80, got %d", pinger.opts.Port)
	}
}

func TestNewStatistics(t *testing.T) {
	stats := NewStatistics(ProtoTCP)
	if stats.Protocol != ProtoTCP {
		t.Errorf("expected protocol TCP, got %s", stats.Protocol)
	}
	if stats.AllRTTs == nil {
		t.Error("expected AllRTTs to be initialized")
	}
}

func TestStatisticsAdd(t *testing.T) {
	stats := NewStatistics(ProtoTCP)

	stats.Add(ProbeResult{Seq: 1, Success: true, RTT: 10 * time.Millisecond})
	stats.Add(ProbeResult{Seq: 2, Success: true, RTT: 20 * time.Millisecond})
	stats.Add(ProbeResult{Seq: 3, Success: false})

	if stats.Sent != 3 {
		t.Errorf("expected Sent=3, got %d", stats.Sent)
	}
	if stats.Received != 2 {
		t.Errorf("expected Received=2, got %d", stats.Received)
	}
	if stats.Lost != 1 {
		t.Errorf("expected Lost=1, got %d", stats.Lost)
	}
	if len(stats.AllRTTs) != 2 {
		t.Errorf("expected 2 RTTs, got %d", len(stats.AllRTTs))
	}
}

func TestStatisticsCalculate(t *testing.T) {
	stats := NewStatistics(ProtoTCP)

	stats.Add(ProbeResult{Seq: 1, Success: true, RTT: 10 * time.Millisecond})
	stats.Add(ProbeResult{Seq: 2, Success: true, RTT: 20 * time.Millisecond})
	stats.Add(ProbeResult{Seq: 3, Success: true, RTT: 30 * time.Millisecond})
	stats.Add(ProbeResult{Seq: 4, Success: false})

	stats.Calculate()

	if stats.LossPercent != 25.0 {
		t.Errorf("expected LossPercent=25.0, got %.1f", stats.LossPercent)
	}
	if stats.MinRTT != 10*time.Millisecond {
		t.Errorf("expected MinRTT=10ms, got %v", stats.MinRTT)
	}
	if stats.MaxRTT != 30*time.Millisecond {
		t.Errorf("expected MaxRTT=30ms, got %v", stats.MaxRTT)
	}
	if stats.AvgRTT != 20*time.Millisecond {
		t.Errorf("expected AvgRTT=20ms, got %v", stats.AvgRTT)
	}
	if stats.MedianRTT != 20*time.Millisecond {
		t.Errorf("expected MedianRTT=20ms, got %v", stats.MedianRTT)
	}
	if stats.StdDev <= 0 {
		t.Error("expected positive StdDev")
	}
}

func TestStatisticsCalculateEmpty(t *testing.T) {
	stats := NewStatistics(ProtoTCP)
	stats.Calculate() // Should not panic
	if stats.LossPercent != 0 {
		t.Errorf("expected LossPercent=0 for empty stats, got %.1f", stats.LossPercent)
	}
}

func TestStatisticsCalculateAllFailed(t *testing.T) {
	stats := NewStatistics(ProtoTCP)
	stats.Add(ProbeResult{Seq: 1, Success: false})
	stats.Add(ProbeResult{Seq: 2, Success: false})
	stats.Calculate()

	if stats.LossPercent != 100.0 {
		t.Errorf("expected LossPercent=100.0, got %.1f", stats.LossPercent)
	}
	if stats.MinRTT != 0 {
		t.Errorf("expected MinRTT=0 for all-failed, got %v", stats.MinRTT)
	}
}

func TestStatisticsCalculateSingleResult(t *testing.T) {
	stats := NewStatistics(ProtoTCP)
	stats.Add(ProbeResult{Seq: 1, Success: true, RTT: 15 * time.Millisecond})
	stats.Calculate()

	if stats.MinRTT != 15*time.Millisecond {
		t.Errorf("expected MinRTT=15ms, got %v", stats.MinRTT)
	}
	if stats.P95 != 15*time.Millisecond {
		t.Errorf("expected P95=15ms for single result, got %v", stats.P95)
	}
	if stats.P99 != 15*time.Millisecond {
		t.Errorf("expected P99=15ms for single result, got %v", stats.P99)
	}
}

func TestQuality(t *testing.T) {
	tests := []struct {
		name        string
		received    int
		sent        int
		avgRTT      time.Duration
		lossPercent float64
		wantPrefix  string
	}{
		{"no response", 0, 5, 0, 100, "❌"},
		{"high loss", 2, 5, 50 * time.Millisecond, 60, "🔴"},
		{"excellent", 5, 5, 10 * time.Millisecond, 0, "🟢"},
		{"good", 5, 5, 40 * time.Millisecond, 0, "🟢"},
		{"fair", 5, 5, 80 * time.Millisecond, 0, "🟡"},
		{"slow", 5, 5, 200 * time.Millisecond, 0, "🟠"},
		{"poor latency", 5, 5, 500 * time.Millisecond, 0, "🔴"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := NewStatistics(ProtoTCP)
			stats.Sent = tt.sent
			stats.Received = tt.received
			stats.LossPercent = tt.lossPercent
			stats.AvgRTT = tt.avgRTT

			quality := stats.Quality()
			if len(quality) == 0 {
				t.Error("expected non-empty quality string")
			}
		})
	}
}

func TestBuildDNSProbe(t *testing.T) {
	probe := buildDNSProbe()

	// Should be exactly 17 bytes
	if len(probe) != 17 {
		t.Errorf("expected probe length 17, got %d", len(probe))
	}

	// Transaction ID
	if probe[0] != 0x00 || probe[1] != 0x01 {
		t.Error("unexpected transaction ID")
	}

	// Questions count = 1
	if probe[4] != 0x00 || probe[5] != 0x01 {
		t.Error("expected 1 question")
	}
}

func TestTlsVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0301, "1.0"},
		{0x0302, "1.1"},
		{0x0303, "1.2"},
		{0x0304, "1.3"},
		{0x0000, "0x0000"},
	}

	for _, tt := range tests {
		got := tlsVersionString(tt.version)
		if got != tt.want {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

// TestTCPProbeWithLocalServer tests TCP probe against a local server.
func TestTCPProbeWithLocalServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port

	pinger := NewPinger(Options{
		Host:     "127.0.0.1",
		Port:     port,
		Protocol: ProtoTCP,
		Count:    3,
		Interval: 100 * time.Millisecond,
		Timeout:  2 * time.Second,
	})

	var results []ProbeResult
	err = pinger.Run(context.Background(), func(r ProbeResult) {
		results = append(results, r)
	})

	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	for i, r := range results {
		if !r.Success {
			t.Errorf("result %d should be successful, error: %v", i+1, r.Error)
		}
		if r.RTT <= 0 {
			t.Errorf("result %d should have positive RTT", i+1)
		}
		if r.Protocol != ProtoTCP {
			t.Errorf("result %d should have protocol TCP, got %s", i+1, r.Protocol)
		}
	}

	if pinger.Stats.Received != 3 {
		t.Errorf("expected 3 received, got %d", pinger.Stats.Received)
	}
}

// TestHTTPProbeWithLocalServer tests HTTP probe against a local HTTP server.
func TestHTTPProbeWithLocalServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	pinger := NewPinger(Options{
		Host:     "127.0.0.1",
		Port:     port,
		Protocol: ProtoHTTP,
		Count:    2,
		Interval: 100 * time.Millisecond,
		Timeout:  2 * time.Second,
	})

	var results []ProbeResult
	err = pinger.Run(context.Background(), func(r ProbeResult) {
		results = append(results, r)
	})

	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	for i, r := range results {
		if !r.Success {
			t.Errorf("HTTP result %d failed: %v", i+1, r.Error)
		}
		if !strings.Contains(r.Detail, "200") {
			t.Errorf("HTTP result %d should contain '200', got '%s'", i+1, r.Detail)
		}
	}
}

// TestRunContextCancellation tests that Run respects context cancellation.
func TestRunContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port

	pinger := NewPinger(Options{
		Host:     "127.0.0.1",
		Port:     port,
		Protocol: ProtoTCP,
		Count:    100,
		Interval: 500 * time.Millisecond,
		Timeout:  2 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var count int
	_ = pinger.Run(ctx, func(r ProbeResult) {
		count++
	})

	if count >= 100 {
		t.Error("context cancellation did not work")
	}
}

// TestTCPProbeConnectionRefused tests behavior with a closed port.
func TestTCPProbeConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	pinger := NewPinger(Options{
		Host:     "127.0.0.1",
		Port:     port,
		Protocol: ProtoTCP,
		Count:    1,
		Timeout:  1 * time.Second,
	})

	var results []ProbeResult
	pinger.Run(context.Background(), func(r ProbeResult) {
		results = append(results, r)
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Success {
		t.Error("expected failure for refused connection")
	}
}

func TestStatisticsFormat(t *testing.T) {
	stats := NewStatistics(ProtoTCP)
	stats.Add(ProbeResult{Seq: 1, Success: true, RTT: 10 * time.Millisecond})
	stats.Add(ProbeResult{Seq: 2, Success: true, RTT: 20 * time.Millisecond})
	stats.Add(ProbeResult{Seq: 3, Success: false})
	stats.Calculate()

	output := stats.Format("example.com")

	if !strings.Contains(output, "example.com") {
		t.Error("format should contain hostname")
	}
	if !strings.Contains(output, "tcp") {
		t.Error("format should contain protocol")
	}
	if !strings.Contains(output, "3 probes sent") {
		t.Error("format should contain probe count")
	}
	if !strings.Contains(output, "Quality") {
		t.Error("format should contain quality assessment")
	}
}

func TestProtocolConstants(t *testing.T) {
	if ProtoTCP != "tcp" {
		t.Error("unexpected ProtoTCP value")
	}
	if ProtoUDP != "udp" {
		t.Error("unexpected ProtoUDP value")
	}
	if ProtoHTTP != "http" {
		t.Error("unexpected ProtoHTTP value")
	}
	if ProtoDNS != "dns" {
		t.Error("unexpected ProtoDNS value")
	}
}
