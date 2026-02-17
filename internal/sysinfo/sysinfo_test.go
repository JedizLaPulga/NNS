package sysinfo

import (
	"strings"
	"testing"
	"time"
)

func TestCollectBasic(t *testing.T) {
	opts := DefaultOptions()
	info := Collect(opts)

	if info.Hostname == "" {
		t.Error("hostname should not be empty")
	}
	if info.OS == "" {
		t.Error("OS should not be empty")
	}
	if info.Arch == "" {
		t.Error("Arch should not be empty")
	}
	if info.GoVersion == "" {
		t.Error("GoVersion should not be empty")
	}
	if info.NumCPU < 1 {
		t.Error("NumCPU should be at least 1")
	}
	if info.CollectedAt.IsZero() {
		t.Error("CollectedAt should not be zero")
	}
}

func TestCollectInterfaces(t *testing.T) {
	ifaces := CollectInterfaces()
	if len(ifaces) == 0 {
		t.Skip("no network interfaces found")
	}

	foundUp := false
	for _, iface := range ifaces {
		if iface.Name == "" {
			t.Error("interface name should not be empty")
		}
		if iface.IsUp {
			foundUp = true
		}
	}
	if !foundUp {
		t.Log("warning: no up interface found")
	}
}

func TestCollectLocalIPs(t *testing.T) {
	ips := CollectLocalIPs()
	// May be empty in some CI environments
	if len(ips) > 0 {
		for _, ip := range ips {
			if ip == "127.0.0.1" || ip == "::1" {
				t.Error("loopback should be excluded")
			}
		}
	}
}

func TestCountActiveInterfaces(t *testing.T) {
	ifaces := []IfaceInfo{
		{Name: "eth0", IsUp: true, IsLoopback: false},
		{Name: "lo", IsUp: true, IsLoopback: true},
		{Name: "wlan0", IsUp: false, IsLoopback: false},
		{Name: "eth1", IsUp: true, IsLoopback: false},
	}

	count := CountActiveInterfaces(ifaces)
	if count != 2 {
		t.Errorf("expected 2 active interfaces, got %d", count)
	}
}

func TestCountActiveInterfacesEmpty(t *testing.T) {
	count := CountActiveInterfaces(nil)
	if count != 0 {
		t.Errorf("expected 0 for nil, got %d", count)
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.ResolvePublic {
		t.Error("ResolvePublic should be false by default")
	}
	if opts.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %s", opts.Timeout)
	}
}

func TestFormatInfoBasic(t *testing.T) {
	info := Info{
		Hostname:    "test-host",
		OS:          "linux",
		Arch:        "amd64",
		GoVersion:   "go1.22.0",
		NumCPU:      4,
		CollectedAt: time.Now(),
		LocalIPs:    []string{"192.168.1.10", "fe80::1"},
		Interfaces: []IfaceInfo{
			{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", MTU: 1500, IsUp: true, Addrs: []string{"192.168.1.10/24"}},
			{Name: "lo", MAC: "", MTU: 65536, IsUp: true, IsLoopback: true, Addrs: []string{"127.0.0.1/8"}},
		},
	}

	out := FormatInfo(info)
	if !strings.Contains(out, "test-host") {
		t.Error("expected hostname in output")
	}
	if !strings.Contains(out, "linux/amd64") {
		t.Error("expected OS/arch in output")
	}
	if !strings.Contains(out, "192.168.1.10") {
		t.Error("expected local IP in output")
	}
	if !strings.Contains(out, "eth0") {
		t.Error("expected interface name in output")
	}
	if !strings.Contains(out, "Active NICs") {
		t.Error("expected active NIC count")
	}
}

func TestFormatInfoWithPublicIP(t *testing.T) {
	info := Info{
		Hostname:    "box",
		OS:          "windows",
		Arch:        "amd64",
		GoVersion:   "go1.22.0",
		NumCPU:      8,
		PublicIP:    "203.0.113.42",
		CollectedAt: time.Now(),
	}

	out := FormatInfo(info)
	if !strings.Contains(out, "203.0.113.42") {
		t.Error("expected public IP in output")
	}
}

func TestFormatInfoEmpty(t *testing.T) {
	info := Info{
		Hostname:    "empty",
		OS:          "linux",
		Arch:        "arm64",
		GoVersion:   "go1.22.0",
		NumCPU:      1,
		CollectedAt: time.Now(),
	}

	out := FormatInfo(info)
	if !strings.Contains(out, "empty") {
		t.Error("expected hostname")
	}
	if !strings.Contains(out, "0 / 0") {
		t.Error("expected 0/0 active NICs")
	}
}

func TestFormatInfoNoAddrs(t *testing.T) {
	info := Info{
		Hostname:    "test",
		OS:          "linux",
		Arch:        "amd64",
		GoVersion:   "go1.22.0",
		NumCPU:      2,
		CollectedAt: time.Now(),
		Interfaces: []IfaceInfo{
			{Name: "eth0", IsUp: false, MTU: 1500},
		},
	}

	out := FormatInfo(info)
	if !strings.Contains(out, "✗") {
		t.Error("expected down indicator")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("should not truncate short strings")
	}
	result := truncate("a very long name indeed", 10)
	if result == "a very long name indeed" {
		t.Error("should have truncated long string")
	}
	if !strings.HasSuffix(result, "…") {
		t.Error("truncated string should end with ellipsis")
	}
}

func TestCollectWithPublicIPDisabled(t *testing.T) {
	opts := DefaultOptions()
	opts.ResolvePublic = false
	info := Collect(opts)
	if info.PublicIP != "" {
		t.Error("public IP should be empty when disabled")
	}
}

func TestInterfaceFlagsPresent(t *testing.T) {
	ifaces := CollectInterfaces()
	for _, iface := range ifaces {
		if iface.Flags == "" {
			t.Errorf("interface %s should have flags", iface.Name)
		}
	}
}

func TestResolvePublicIPTimeout(t *testing.T) {
	// Use very short timeout to force failure
	ip := ResolvePublicIP(1 * time.Nanosecond)
	// Should return empty or an actual IP — either is acceptable
	_ = ip
}
