// Package sysinfo collects system and network environment information.
package sysinfo

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Info holds collected system and network information.
type Info struct {
	Hostname    string      `json:"hostname"`
	OS          string      `json:"os"`
	Arch        string      `json:"arch"`
	GoVersion   string      `json:"go_version"`
	NumCPU      int         `json:"num_cpu"`
	Interfaces  []IfaceInfo `json:"interfaces"`
	LocalIPs    []string    `json:"local_ips"`
	PublicIP    string      `json:"public_ip,omitempty"`
	CollectedAt time.Time   `json:"collected_at"`
}

// IfaceInfo holds per-interface detail.
type IfaceInfo struct {
	Name       string   `json:"name"`
	MAC        string   `json:"mac"`
	MTU        int      `json:"mtu"`
	Flags      string   `json:"flags"`
	Addrs      []string `json:"addrs"`
	IsUp       bool     `json:"is_up"`
	IsLoopback bool     `json:"is_loopback"`
}

// Options configures collection behavior.
type Options struct {
	ResolvePublic bool
	Timeout       time.Duration
}

// DefaultOptions returns sane defaults.
func DefaultOptions() Options {
	return Options{
		ResolvePublic: false,
		Timeout:       5 * time.Second,
	}
}

// Collect gathers system and network information.
func Collect(opts Options) Info {
	info := Info{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
		NumCPU:      runtime.NumCPU(),
		CollectedAt: time.Now(),
	}

	hostname, err := os.Hostname()
	if err != nil {
		info.Hostname = "(unknown)"
	} else {
		info.Hostname = hostname
	}

	info.Interfaces = CollectInterfaces()
	info.LocalIPs = CollectLocalIPs()

	if opts.ResolvePublic {
		info.PublicIP = ResolvePublicIP(opts.Timeout)
	}

	return info
}

// CollectInterfaces enumerates network interfaces.
func CollectInterfaces() []IfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []IfaceInfo
	for _, iface := range ifaces {
		ii := IfaceInfo{
			Name:       iface.Name,
			MAC:        iface.HardwareAddr.String(),
			MTU:        iface.MTU,
			Flags:      iface.Flags.String(),
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ii.Addrs = append(ii.Addrs, addr.String())
			}
		}
		result = append(result, ii)
	}
	return result
}

// CollectLocalIPs returns non-loopback IPs.
func CollectLocalIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.IsLoopback() {
			continue
		}
		ips = append(ips, ipNet.IP.String())
	}
	return ips
}

// ResolvePublicIP attempts to determine the public IP via DNS (OpenDNS).
func ResolvePublicIP(timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", "208.67.222.222:53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "myip.opendns.com")
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

// CountActiveInterfaces returns the number of up, non-loopback interfaces.
func CountActiveInterfaces(ifaces []IfaceInfo) int {
	n := 0
	for _, iface := range ifaces {
		if iface.IsUp && !iface.IsLoopback {
			n++
		}
	}
	return n
}

// FormatInfo returns a human-readable representation of system info.
func FormatInfo(info Info) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Hostname:     %s\n", info.Hostname))
	sb.WriteString(fmt.Sprintf("  OS:           %s/%s\n", info.OS, info.Arch))
	sb.WriteString(fmt.Sprintf("  Go Version:   %s\n", info.GoVersion))
	sb.WriteString(fmt.Sprintf("  CPUs:         %d\n", info.NumCPU))
	sb.WriteString(fmt.Sprintf("  Collected:    %s\n", info.CollectedAt.Format(time.RFC3339)))

	if len(info.LocalIPs) > 0 {
		sb.WriteString(fmt.Sprintf("\n  Local IPs:    %s\n", strings.Join(info.LocalIPs, ", ")))
	}

	if info.PublicIP != "" {
		sb.WriteString(fmt.Sprintf("  Public IP:    %s\n", info.PublicIP))
	}

	active := CountActiveInterfaces(info.Interfaces)
	sb.WriteString(fmt.Sprintf("  Active NICs:  %d / %d\n", active, len(info.Interfaces)))

	if len(info.Interfaces) > 0 {
		sb.WriteString("\n  ── Interfaces ──\n")
		sb.WriteString(fmt.Sprintf("  %-20s %-6s %-19s %-6s %s\n",
			"Name", "Up", "MAC", "MTU", "Addresses"))
		sb.WriteString(fmt.Sprintf("  %-20s %-6s %-19s %-6s %s\n",
			"───────────────────", "─────", "──────────────────", "─────", "─────────"))
		for _, iface := range info.Interfaces {
			up := "✗"
			if iface.IsUp {
				up = "✓"
			}
			mac := iface.MAC
			if mac == "" {
				mac = "-"
			}
			addrStr := "-"
			if len(iface.Addrs) > 0 {
				addrStr = strings.Join(iface.Addrs, ", ")
			}
			sb.WriteString(fmt.Sprintf("  %-20s %-6s %-19s %-6d %s\n",
				truncate(iface.Name, 20), up, mac, iface.MTU, addrStr))
		}
	}

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
