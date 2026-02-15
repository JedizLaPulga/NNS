package netcalc

import (
	"strings"
	"testing"
)

func TestCalculateCIDR(t *testing.T) {
	info, err := Calculate("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if info.PrefixLen != 24 {
		t.Errorf("expected prefix 24, got %d", info.PrefixLen)
	}
	if info.HostBits != 8 {
		t.Errorf("expected 8 host bits, got %d", info.HostBits)
	}
	if info.NetworkAddr.String() != "192.168.1.0" {
		t.Errorf("unexpected network addr: %s", info.NetworkAddr)
	}
	if info.Broadcast.String() != "192.168.1.255" {
		t.Errorf("unexpected broadcast: %s", info.Broadcast)
	}
	if info.TotalHosts.Int64() != 256 {
		t.Errorf("expected 256 total hosts, got %s", info.TotalHosts)
	}
	if info.UsableHosts.Int64() != 254 {
		t.Errorf("expected 254 usable hosts, got %s", info.UsableHosts)
	}
}

func TestCalculateBareIP(t *testing.T) {
	info, err := Calculate("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if info.PrefixLen != 32 {
		t.Errorf("expected /32 for bare IP, got /%d", info.PrefixLen)
	}
}

func TestCalculateInvalid(t *testing.T) {
	_, err := Calculate("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid input")
	}
}

func TestCalculateSmallSubnet(t *testing.T) {
	info, err := Calculate("10.0.0.0/31")
	if err != nil {
		t.Fatal(err)
	}
	if info.HostBits != 1 {
		t.Errorf("expected 1 host bit, got %d", info.HostBits)
	}
}

func TestCalculateSlash32(t *testing.T) {
	info, err := Calculate("10.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	if info.TotalHosts.Int64() != 1 {
		t.Errorf("expected 1 total host, got %s", info.TotalHosts)
	}
}

func TestCalculateClassA(t *testing.T) {
	info, err := Calculate("10.0.0.1/8")
	if err != nil {
		t.Fatal(err)
	}
	if info.IPClass != "A" {
		t.Errorf("expected class A, got %s", info.IPClass)
	}
	if !info.IsPrivate {
		t.Error("10.x should be private")
	}
}

func TestCalculateClassB(t *testing.T) {
	info, err := Calculate("172.16.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	if info.IPClass != "B" {
		t.Errorf("expected class B, got %s", info.IPClass)
	}
}

func TestCalculateClassC(t *testing.T) {
	info, err := Calculate("192.168.1.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if info.IPClass != "C" {
		t.Errorf("expected class C, got %s", info.IPClass)
	}
}

func TestCalculateMulticast(t *testing.T) {
	info, err := Calculate("224.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.IPClass, "Multicast") {
		t.Errorf("expected multicast class, got %s", info.IPClass)
	}
}

func TestCalculatePrivateRanges(t *testing.T) {
	tests := []struct {
		cidr    string
		private bool
	}{
		{"10.0.0.1/8", true},
		{"172.16.0.1/12", true},
		{"192.168.0.1/16", true},
		{"127.0.0.1/8", true},
		{"8.8.8.8/32", false},
	}
	for _, tt := range tests {
		info, err := Calculate(tt.cidr)
		if err != nil {
			t.Errorf("Calculate(%s) error: %v", tt.cidr, err)
			continue
		}
		if info.IsPrivate != tt.private {
			t.Errorf("%s: expected private=%v, got %v", tt.cidr, tt.private, info.IsPrivate)
		}
	}
}

func TestNetmaskAndWildcard(t *testing.T) {
	info, err := Calculate("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if info.Netmask.String() != "ffffff00" {
		// net.IP.String() for mask bytes gives hex; we compare the mask bytes
		if len(info.Netmask) != 4 || info.Netmask[0] != 255 || info.Netmask[1] != 255 || info.Netmask[2] != 255 || info.Netmask[3] != 0 {
			t.Errorf("unexpected netmask: %v", info.Netmask)
		}
	}
	if len(info.Wildcard) != 4 || info.Wildcard[0] != 0 || info.Wildcard[1] != 0 || info.Wildcard[2] != 0 || info.Wildcard[3] != 255 {
		t.Errorf("unexpected wildcard: %v", info.Wildcard)
	}
}

func TestBinaryRepresentation(t *testing.T) {
	info, err := Calculate("192.168.1.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if info.Binary == "" {
		t.Error("expected non-empty binary")
	}
	if !strings.Contains(info.Binary, ".") {
		t.Error("binary should contain dot separators")
	}
}

func TestAddToIP(t *testing.T) {
	result, err := AddToIP("10.0.0.1", 5)
	if err != nil {
		t.Fatal(err)
	}
	if result.String() != "10.0.0.6" {
		t.Errorf("expected 10.0.0.6, got %s", result)
	}
}

func TestAddToIPNegative(t *testing.T) {
	result, err := AddToIP("10.0.0.10", -5)
	if err != nil {
		t.Fatal(err)
	}
	if result.String() != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %s", result)
	}
}

func TestAddToIPInvalid(t *testing.T) {
	_, err := AddToIP("not-an-ip", 1)
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestIPRange(t *testing.T) {
	ips, err := IPRange("10.0.0.1", "10.0.0.5", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 5 {
		t.Errorf("expected 5 IPs, got %d", len(ips))
	}
	if ips[0].String() != "10.0.0.1" {
		t.Errorf("first IP should be 10.0.0.1, got %s", ips[0])
	}
	if ips[4].String() != "10.0.0.5" {
		t.Errorf("last IP should be 10.0.0.5, got %s", ips[4])
	}
}

func TestIPRangeCapped(t *testing.T) {
	ips, err := IPRange("10.0.0.0", "10.0.0.255", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 10 {
		t.Errorf("expected 10 IPs (capped), got %d", len(ips))
	}
}

func TestIPRangeInvalid(t *testing.T) {
	_, err := IPRange("bad", "10.0.0.5", 10)
	if err == nil {
		t.Error("expected error for invalid start")
	}
}

func TestIPRangeReversed(t *testing.T) {
	_, err := IPRange("10.0.0.5", "10.0.0.1", 10)
	if err == nil {
		t.Error("expected error for reversed range")
	}
}

func TestIPToBinary(t *testing.T) {
	bin, err := IPToBinary("192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bin, "11000000") {
		t.Errorf("binary should start with 11000000, got %s", bin)
	}
}

func TestIPToBinaryInvalid(t *testing.T) {
	_, err := IPToBinary("not-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestFormatInfo(t *testing.T) {
	info, _ := Calculate("192.168.1.0/24")
	output := FormatInfo(info)
	if !strings.Contains(output, "192.168.1.0") {
		t.Error("should contain network address")
	}
	if !strings.Contains(output, "Broadcast") {
		t.Error("should contain broadcast label")
	}
	if !strings.Contains(output, "Private") {
		t.Error("should contain private indicator")
	}
}

func TestFirstLastUsable(t *testing.T) {
	info, err := Calculate("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if info.FirstUsable.String() != "10.0.0.1" {
		t.Errorf("first usable should be 10.0.0.1, got %s", info.FirstUsable)
	}
	if info.LastUsable.String() != "10.0.0.254" {
		t.Errorf("last usable should be 10.0.0.254, got %s", info.LastUsable)
	}
}
