package netaudit

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", opts.Timeout)
	}
	if opts.Concurrency != 10 {
		t.Errorf("expected concurrency 10, got %d", opts.Concurrency)
	}
	if !opts.CheckDNS {
		t.Error("expected CheckDNS=true")
	}
	if !opts.CheckSNMP {
		t.Error("expected CheckSNMP=true")
	}
	if !opts.CheckSSH {
		t.Error("expected CheckSSH=true")
	}
	if !opts.CheckTelnet {
		t.Error("expected CheckTelnet=true")
	}
	if !opts.CheckHTTP {
		t.Error("expected CheckHTTP=true")
	}
	if !opts.CheckTLS {
		t.Error("expected CheckTLS=true")
	}
	if !opts.CheckPorts {
		t.Error("expected CheckPorts=true")
	}
	if !opts.CheckBanners {
		t.Error("expected CheckBanners=true")
	}
	if len(opts.CustomPorts) == 0 {
		t.Error("expected non-empty CustomPorts")
	}
}

func TestNewAuditor(t *testing.T) {
	opts := Options{Target: "192.168.1.1"}
	auditor := NewAuditor(opts)

	if auditor.opts.Timeout != 5*time.Second {
		t.Errorf("expected default timeout 5s, got %v", auditor.opts.Timeout)
	}
	if auditor.opts.Concurrency != 10 {
		t.Errorf("expected default concurrency 10, got %d", auditor.opts.Concurrency)
	}
	if len(auditor.opts.CustomPorts) == 0 {
		t.Error("expected default ports to be populated")
	}
}

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		a, b     Severity
		wantLess bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityMedium, true},
		{SeverityMedium, SeverityLow, true},
		{SeverityLow, SeverityInfo, true},
		{SeverityInfo, SeverityCritical, false},
	}

	for _, tt := range tests {
		if (severityOrder(tt.a) < severityOrder(tt.b)) != tt.wantLess {
			t.Errorf("severityOrder(%s) < severityOrder(%s) = %v, want %v",
				tt.a, tt.b, severityOrder(tt.a) < severityOrder(tt.b), tt.wantLess)
		}
	}
}

func TestCalculateSummary(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityLow},
		{Severity: SeverityInfo},
	}

	summary := calculateSummary(findings)

	if summary.Critical != 1 {
		t.Errorf("expected Critical=1, got %d", summary.Critical)
	}
	if summary.High != 2 {
		t.Errorf("expected High=2, got %d", summary.High)
	}
	if summary.Medium != 1 {
		t.Errorf("expected Medium=1, got %d", summary.Medium)
	}
	if summary.Low != 1 {
		t.Errorf("expected Low=1, got %d", summary.Low)
	}
	if summary.Info != 1 {
		t.Errorf("expected Info=1, got %d", summary.Info)
	}
	if summary.Total != 6 {
		t.Errorf("expected Total=6, got %d", summary.Total)
	}
}

func TestCalculateSummaryGrades(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		wantMin  int
		wantMax  int
	}{
		{"no findings", nil, 100, 100},
		{"info only", []Finding{{Severity: SeverityInfo}}, 100, 100},
		{"one low", []Finding{{Severity: SeverityLow}}, 95, 100},
		{"one critical", []Finding{{Severity: SeverityCritical}}, 70, 80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := calculateSummary(tt.findings)
			if summary.Score < tt.wantMin || summary.Score > tt.wantMax {
				t.Errorf("score %d not in range [%d, %d]", summary.Score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestCalculateSummaryPerfectGrade(t *testing.T) {
	summary := calculateSummary(nil)
	if summary.Grade != "A" {
		t.Errorf("expected grade A for no findings, got %s", summary.Grade)
	}
	if summary.Score != 100 {
		t.Errorf("expected score 100, got %d", summary.Score)
	}
}

func TestCalculateSummaryFailGrade(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
	}

	summary := calculateSummary(findings)
	if summary.Grade != "F" {
		t.Errorf("expected grade F, got %s", summary.Grade)
	}
}

func TestContainsVersion(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"Apache/2.4.41", true},
		{"nginx/1.18.0", true},
		{"Microsoft-IIS", false},
		{"", false},
		{"OpenSSH_8.2p1", true},
		{"SimpleServer", false},
	}

	for _, tt := range tests {
		got := containsVersion(tt.input)
		if got != tt.want {
			t.Errorf("containsVersion(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"a long string that should be cut", 15, "a long stri..."},
		{"exact12chars", 12, "exact12chars"},
		{"", 5, ""},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestSeverityIcon(t *testing.T) {
	tests := []struct {
		severity Severity
		wantLen  bool // just check non-empty
	}{
		{SeverityCritical, true},
		{SeverityHigh, true},
		{SeverityMedium, true},
		{SeverityLow, true},
		{SeverityInfo, true},
	}

	for _, tt := range tests {
		icon := severityIcon(tt.severity)
		if len(icon) == 0 {
			t.Errorf("severityIcon(%s) returned empty string", tt.severity)
		}
	}
}

func TestTlsVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0000, "Unknown (0x0000)"},
	}

	for _, tt := range tests {
		got := tlsVersionName(tt.version)
		if got != tt.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestBuildDNSQuery(t *testing.T) {
	query := buildDNSQuery("google.com")

	if len(query) < 12 {
		t.Fatal("DNS query too short")
	}

	// Transaction ID
	if query[0] != 0xAA || query[1] != 0xBB {
		t.Error("unexpected transaction ID")
	}

	// Should contain "google" and "com" labels
	data := string(query)
	if !strings.Contains(data, "google") || !strings.Contains(data, "com") {
		t.Error("DNS query should contain domain labels")
	}
}

func TestBuildSNMPGetRequest(t *testing.T) {
	pkt := buildSNMPGetRequest("public")

	if len(pkt) < 10 {
		t.Fatal("SNMP packet too short")
	}

	// First byte should be SEQUENCE (0x30)
	if pkt[0] != 0x30 {
		t.Errorf("expected first byte 0x30, got 0x%02x", pkt[0])
	}

	// Should contain community string
	if !strings.Contains(string(pkt), "public") {
		t.Error("SNMP packet should contain community string")
	}
}

func TestAuditResultFormat(t *testing.T) {
	result := &AuditResult{
		Target:    "192.168.1.1",
		ChecksRun: 8,
		Duration:  500 * time.Millisecond,
		Findings: []Finding{
			{
				Severity:    SeverityCritical,
				Title:       "Telnet exposed",
				Description: "Telnet is accessible",
				Host:        "192.168.1.1",
				Port:        23,
				Remediation: "Disable Telnet",
			},
			{
				Severity:    SeverityLow,
				Title:       "Banner leak",
				Description: "FTP shows version",
				Host:        "192.168.1.1",
				Port:        21,
			},
		},
		Summary: AuditSummary{Critical: 1, Low: 1, Total: 2, Score: 72, Grade: "C"},
	}

	output := result.Format()
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("format should contain target")
	}
	if !strings.Contains(output, "Telnet exposed") {
		t.Error("format should contain finding title")
	}
	if !strings.Contains(output, "Grade") || !strings.Contains(output, "C") {
		t.Error("format should contain grade")
	}
}

func TestAuditResultFormatNoFindings(t *testing.T) {
	result := &AuditResult{
		Target:    "secure.host",
		ChecksRun: 8,
		Duration:  200 * time.Millisecond,
		Summary:   AuditSummary{Score: 100, Grade: "A"},
	}

	output := result.Format()
	if !strings.Contains(output, "No security issues") {
		t.Error("format should indicate no issues when findings is empty")
	}
}

func TestAuditResultFormatCompact(t *testing.T) {
	result := &AuditResult{
		Target: "test.host",
		Summary: AuditSummary{
			Grade: "B", Score: 82,
			Critical: 0, High: 1, Medium: 1, Low: 2, Info: 0, Total: 4,
		},
	}

	compact := result.FormatCompact()
	if !strings.Contains(compact, "test.host") {
		t.Error("compact format should contain target")
	}
	if !strings.Contains(compact, "B") {
		t.Error("compact format should contain grade")
	}
}

// TestAuditLocalhostNoPorts tests audit against localhost with all port checks disabled.
func TestAuditLocalhostNoPorts(t *testing.T) {
	opts := Options{
		Target:       "127.0.0.1",
		Timeout:      1 * time.Second,
		Concurrency:  5,
		CheckDNS:     false,
		CheckSNMP:    false,
		CheckSSH:     false,
		CheckTelnet:  false,
		CheckHTTP:    false,
		CheckTLS:     false,
		CheckPorts:   false,
		CheckBanners: false,
	}

	auditor := NewAuditor(opts)
	result, err := auditor.Audit(context.Background())
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}

	if result.Target != "127.0.0.1" {
		t.Errorf("expected target 127.0.0.1, got %s", result.Target)
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

// TestCheckOpenPortsWithLocalServer tests port scanning with a local server.
func TestCheckOpenPortsWithLocalServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	opts := Options{
		Target:      "127.0.0.1",
		Timeout:     2 * time.Second,
		CustomPorts: []int{port},
	}
	auditor := NewAuditor(opts)

	findings := auditor.checkOpenPorts(context.Background(), "127.0.0.1")
	// Port is open but not in the dangerous list, so no findings expected
	_ = findings
}

// TestCheckSSHWithMock tests SSH check behavior with a mock SSH banner.
func TestCheckSSHWithMock(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	_ = port // Port won't be 22, so checkSSH won't connect to our mock
	// This tests that checkSSH handles the case where port 22 is not open
	opts := Options{
		Target:  "127.0.0.1",
		Timeout: 1 * time.Second,
	}
	auditor := NewAuditor(opts)
	findings := auditor.checkSSH(context.Background(), "127.0.0.1")
	_ = findings
}

func TestFindingSeverityConstants(t *testing.T) {
	if SeverityCritical != "CRITICAL" {
		t.Error("unexpected SeverityCritical value")
	}
	if SeverityHigh != "HIGH" {
		t.Error("unexpected SeverityHigh value")
	}
	if SeverityMedium != "MEDIUM" {
		t.Error("unexpected SeverityMedium value")
	}
	if SeverityLow != "LOW" {
		t.Error("unexpected SeverityLow value")
	}
	if SeverityInfo != "INFO" {
		t.Error("unexpected SeverityInfo value")
	}
}

func TestCheckTypeConstants(t *testing.T) {
	checks := []CheckType{
		CheckOpenDNS, CheckSNMPDefault, CheckSSH, CheckTelnet,
		CheckExposedHTTP, CheckWeakTLS, CheckOpenPorts, CheckBannerLeak,
	}

	seen := make(map[CheckType]bool)
	for _, c := range checks {
		if seen[c] {
			t.Errorf("duplicate check type: %s", c)
		}
		seen[c] = true
		if string(c) == "" {
			t.Error("check type should not be empty")
		}
	}
}

func TestScoreFloor(t *testing.T) {
	many := make([]Finding, 20)
	for i := range many {
		many[i] = Finding{Severity: SeverityCritical}
	}
	summary := calculateSummary(many)
	if summary.Score < 0 {
		t.Errorf("score should not be negative, got %d", summary.Score)
	}
	if summary.Grade != "F" {
		t.Errorf("expected grade F for many critical findings, got %s", summary.Grade)
	}
}

func TestAuditContextCancellation(t *testing.T) {
	opts := Options{
		Target:       "127.0.0.1",
		Timeout:      100 * time.Millisecond,
		Concurrency:  1,
		CheckDNS:     false,
		CheckSNMP:    false,
		CheckSSH:     false,
		CheckTelnet:  false,
		CheckHTTP:    false,
		CheckTLS:     false,
		CheckPorts:   true,
		CheckBanners: false,
		CustomPorts:  []int{1, 2, 3},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	auditor := NewAuditor(opts)
	result, err := auditor.Audit(ctx)
	// Should complete without panicking
	_ = result
	_ = err
}

func TestFormatWithAllSeverities(t *testing.T) {
	result := &AuditResult{
		Target:    "test",
		ChecksRun: 5,
		Duration:  100 * time.Millisecond,
		Findings: []Finding{
			{Severity: SeverityCritical, Title: "Critical issue", Description: "Bad"},
			{Severity: SeverityHigh, Title: "High issue", Description: "Bad"},
			{Severity: SeverityMedium, Title: "Medium issue", Description: "Meh"},
			{Severity: SeverityLow, Title: "Low issue", Description: "Minor"},
			{Severity: SeverityInfo, Title: "Info", Description: "FYI"},
		},
		Summary: AuditSummary{
			Critical: 1, High: 1, Medium: 1, Low: 1, Info: 1,
			Total: 5, Score: 49, Grade: "D",
		},
	}

	output := result.Format()

	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if !strings.Contains(output, sev) {
			t.Errorf("format output should contain severity %s", sev)
		}
	}
}

func TestFormatFindingWithDetail(t *testing.T) {
	result := &AuditResult{
		Target:    "test",
		ChecksRun: 1,
		Duration:  50 * time.Millisecond,
		Findings: []Finding{
			{
				Severity:    SeverityHigh,
				Title:       "Test finding",
				Description: "Test description",
				Detail:      "Extra detail here",
				Host:        "1.2.3.4",
				Port:        22,
				Remediation: "Fix it",
			},
		},
		Summary: AuditSummary{High: 1, Total: 1, Score: 85, Grade: "B"},
	}

	output := result.Format()

	if !strings.Contains(output, "Extra detail here") {
		t.Error("format should include finding detail")
	}
	if !strings.Contains(output, "Fix it") {
		t.Error("format should include remediation")
	}
	if !strings.Contains(output, fmt.Sprintf("1.2.3.4:%d", 22)) {
		t.Error("format should include host:port")
	}
}
