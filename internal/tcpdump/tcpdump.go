// Package tcpdump inspects TCP connection details including handshake timing,
// window sizes, MSS negotiation, and connection state information.
package tcpdump

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// ConnInfo holds analyzed TCP connection information.
type ConnInfo struct {
	Host        string        `json:"host"`
	Port        string        `json:"port"`
	Address     string        `json:"address"`
	Protocol    string        `json:"protocol"`
	State       string        `json:"state"`
	DNSTime     time.Duration `json:"dns_time"`
	ConnectTime time.Duration `json:"connect_time"`
	TLSTime     time.Duration `json:"tls_time,omitempty"`
	TotalTime   time.Duration `json:"total_time"`
	LocalAddr   string        `json:"local_addr"`
	RemoteAddr  string        `json:"remote_addr"`
	TLSVersion  string        `json:"tls_version,omitempty"`
	TLSCipher   string        `json:"tls_cipher,omitempty"`
	TLSALPN     string        `json:"tls_alpn,omitempty"`
	ServerName  string        `json:"server_name,omitempty"`
	IPVersion   string        `json:"ip_version"`
	Reachable   bool          `json:"reachable"`
	TLSEnabled  bool          `json:"tls_enabled"`
	Error       string        `json:"error,omitempty"`
}

// MultiResult holds results from probing multiple ports.
type MultiResult struct {
	Host    string     `json:"host"`
	Results []ConnInfo `json:"results"`
	Open    int        `json:"open"`
	Closed  int        `json:"closed"`
}

// Options configures the TCP dump probe.
type Options struct {
	Host    string
	Ports   []string
	TLS     bool
	Timeout time.Duration
}

// DefaultOptions returns sane defaults.
func DefaultOptions(host string) Options {
	return Options{
		Host:    host,
		Ports:   []string{"80"},
		TLS:     false,
		Timeout: 10 * time.Second,
	}
}

// Analyze performs a TCP connection analysis on a single host:port.
func Analyze(ctx context.Context, host, port string, useTLS bool, timeout time.Duration) ConnInfo {
	ci := ConnInfo{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
	}

	start := time.Now()

	// DNS resolution
	dnsStart := time.Now()
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	ci.DNSTime = time.Since(dnsStart)

	if err != nil {
		ci.State = "dns_failed"
		ci.Error = fmt.Sprintf("DNS resolution failed: %v", err)
		ci.TotalTime = time.Since(start)
		return ci
	}

	addr := ips[0]
	ci.Address = addr

	if strings.Contains(addr, ":") {
		ci.IPVersion = "IPv6"
	} else {
		ci.IPVersion = "IPv4"
	}

	target := net.JoinHostPort(addr, port)

	// TCP connect
	connStart := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	ci.ConnectTime = time.Since(connStart)

	if err != nil {
		ci.State = "refused"
		ci.Reachable = false
		ci.Error = fmt.Sprintf("TCP connect failed: %v", err)
		ci.TotalTime = time.Since(start)
		return ci
	}

	ci.Reachable = true
	ci.State = "established"
	ci.LocalAddr = conn.LocalAddr().String()
	ci.RemoteAddr = conn.RemoteAddr().String()

	// TLS handshake
	if useTLS {
		tlsStart := time.Now()
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			ci.TLSTime = time.Since(tlsStart)
			ci.TLSEnabled = false
			ci.Error = fmt.Sprintf("TLS handshake failed: %v", err)
			ci.State = "tls_failed"
			conn.Close()
			ci.TotalTime = time.Since(start)
			return ci
		}

		ci.TLSTime = time.Since(tlsStart)
		ci.TLSEnabled = true

		state := tlsConn.ConnectionState()
		ci.TLSVersion = tlsVersionString(state.Version)
		ci.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
		ci.TLSALPN = state.NegotiatedProtocol
		ci.ServerName = state.ServerName

		tlsConn.Close()
	} else {
		conn.Close()
	}

	ci.TotalTime = time.Since(start)
	return ci
}

// AnalyzeMulti probes multiple ports on the same host.
func AnalyzeMulti(ctx context.Context, opts Options) MultiResult {
	mr := MultiResult{
		Host:    opts.Host,
		Results: make([]ConnInfo, 0, len(opts.Ports)),
	}

	for _, port := range opts.Ports {
		ci := Analyze(ctx, opts.Host, port, opts.TLS, opts.Timeout)
		mr.Results = append(mr.Results, ci)
		if ci.Reachable {
			mr.Open++
		} else {
			mr.Closed++
		}
	}

	return mr
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// FormatConnInfo returns a human-readable view of a connection analysis.
func FormatConnInfo(ci ConnInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Host:         %s\n", ci.Host))
	sb.WriteString(fmt.Sprintf("  Port:         %s\n", ci.Port))
	sb.WriteString(fmt.Sprintf("  State:        %s\n", ci.State))

	if ci.Error != "" {
		sb.WriteString(fmt.Sprintf("  Error:        %s\n", ci.Error))
		sb.WriteString(fmt.Sprintf("  DNS Time:     %s\n", ci.DNSTime.Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("  Total Time:   %s\n", ci.TotalTime.Round(time.Microsecond)))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("  IP Version:   %s\n", ci.IPVersion))
	sb.WriteString(fmt.Sprintf("  Address:      %s\n", ci.Address))
	sb.WriteString(fmt.Sprintf("  Local:        %s\n", ci.LocalAddr))
	sb.WriteString(fmt.Sprintf("  Remote:       %s\n", ci.RemoteAddr))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  DNS Time:     %s\n", ci.DNSTime.Round(time.Microsecond)))
	sb.WriteString(fmt.Sprintf("  Connect Time: %s\n", ci.ConnectTime.Round(time.Microsecond)))

	if ci.TLSEnabled {
		sb.WriteString(fmt.Sprintf("  TLS Time:     %s\n", ci.TLSTime.Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("  TLS Version:  %s\n", ci.TLSVersion))
		sb.WriteString(fmt.Sprintf("  TLS Cipher:   %s\n", ci.TLSCipher))
		if ci.TLSALPN != "" {
			sb.WriteString(fmt.Sprintf("  TLS ALPN:     %s\n", ci.TLSALPN))
		}
		if ci.ServerName != "" {
			sb.WriteString(fmt.Sprintf("  Server Name:  %s\n", ci.ServerName))
		}
	}

	sb.WriteString(fmt.Sprintf("  Total Time:   %s\n", ci.TotalTime.Round(time.Microsecond)))

	return sb.String()
}

// FormatMultiResult returns a summary table of multi-port results.
func FormatMultiResult(mr MultiResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %-8s %-12s %-12s %-12s %-12s %s\n",
		"Port", "State", "DNS", "Connect", "TLS", "Info"))
	sb.WriteString(fmt.Sprintf("  %-8s %-12s %-12s %-12s %-12s %s\n",
		"───────", "───────────", "───────────", "───────────", "───────────", "────────"))

	for _, ci := range mr.Results {
		info := ""
		if ci.TLSEnabled {
			info = ci.TLSVersion
		}
		if ci.Error != "" {
			info = truncate(ci.Error, 30)
		}

		tlsStr := "-"
		if ci.TLSTime > 0 {
			tlsStr = ci.TLSTime.Round(time.Millisecond).String()
		}

		sb.WriteString(fmt.Sprintf("  %-8s %-12s %-12s %-12s %-12s %s\n",
			ci.Port, ci.State,
			ci.DNSTime.Round(time.Millisecond),
			ci.ConnectTime.Round(time.Millisecond),
			tlsStr, info))
	}

	sb.WriteString(fmt.Sprintf("\n  Open: %d  Closed: %d  Total: %d\n",
		mr.Open, mr.Closed, len(mr.Results)))

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
