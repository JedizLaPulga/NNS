package cidr

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		cidr        string
		wantNetwork string
		wantTotal   int
		wantUsable  int
		wantErr     bool
	}{
		{"192.168.1.0/24", "192.168.1.0/24", 256, 254, false},
		{"10.0.0.0/8", "10.0.0.0/8", 16777216, 16777214, false},
		{"172.16.0.0/16", "172.16.0.0/16", 65536, 65534, false},
		{"192.168.1.1/32", "192.168.1.1/32", 1, 1, false},
		{"invalid", "", 0, 0, true},
	}

	for _, tt := range tests {
		subnet, err := Parse(tt.cidr)
		if (err != nil) != tt.wantErr {
			t.Errorf("Parse(%q) error = %v, wantErr %v", tt.cidr, err, tt.wantErr)
			continue
		}
		if err == nil {
			if subnet.CIDR != tt.wantNetwork {
				t.Errorf("Parse(%q).CIDR = %q, want %q", tt.cidr, subnet.CIDR, tt.wantNetwork)
			}
			if subnet.TotalHosts != tt.wantTotal {
				t.Errorf("Parse(%q).TotalHosts = %d, want %d", tt.cidr, subnet.TotalHosts, tt.wantTotal)
			}
			if subnet.UsableHosts != tt.wantUsable {
				t.Errorf("Parse(%q).UsableHosts = %d, want %d", tt.cidr, subnet.UsableHosts, tt.wantUsable)
			}
		}
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		cidr string
		ip   string
		want bool
	}{
		{"192.168.1.0/24", "192.168.1.100", true},
		{"192.168.1.0/24", "192.168.2.1", false},
		{"10.0.0.0/8", "10.255.255.255", true},
		{"10.0.0.0/8", "11.0.0.1", false},
	}

	for _, tt := range tests {
		got, err := Contains(tt.cidr, tt.ip)
		if err != nil {
			t.Errorf("Contains(%q, %q) error = %v", tt.cidr, tt.ip, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", tt.cidr, tt.ip, got, tt.want)
		}
	}
}

func TestSplit(t *testing.T) {
	subnets, err := Split("192.168.0.0/24", 26)
	if err != nil {
		t.Fatalf("Split() error = %v", err)
	}

	if len(subnets) != 4 {
		t.Errorf("Split() returned %d subnets, want 4", len(subnets))
	}

	expected := []string{
		"192.168.0.0/26",
		"192.168.0.64/26",
		"192.168.0.128/26",
		"192.168.0.192/26",
	}

	for i, want := range expected {
		if subnets[i] != want {
			t.Errorf("Split()[%d] = %q, want %q", i, subnets[i], want)
		}
	}
}

func TestIPToInt(t *testing.T) {
	tests := []struct {
		ip   string
		want uint32
	}{
		{"0.0.0.0", 0},
		{"0.0.0.1", 1},
		{"0.0.1.0", 256},
		{"192.168.1.1", 3232235777},
		{"255.255.255.255", 4294967295},
	}

	for _, tt := range tests {
		got, err := IPToInt(tt.ip)
		if err != nil {
			t.Errorf("IPToInt(%q) error = %v", tt.ip, err)
			continue
		}
		if got != tt.want {
			t.Errorf("IPToInt(%q) = %d, want %d", tt.ip, got, tt.want)
		}
	}
}

func TestIntToIP(t *testing.T) {
	tests := []struct {
		n    uint32
		want string
	}{
		{0, "0.0.0.0"},
		{1, "0.0.0.1"},
		{256, "0.0.1.0"},
		{3232235777, "192.168.1.1"},
		{4294967295, "255.255.255.255"},
	}

	for _, tt := range tests {
		got := IntToIP(tt.n)
		if got != tt.want {
			t.Errorf("IntToIP(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestMaskToPrefix(t *testing.T) {
	tests := []struct {
		mask string
		want int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"255.0.0.0", 8},
		{"255.255.255.255", 32},
		{"0.0.0.0", 0},
	}

	for _, tt := range tests {
		got, err := MaskToPrefix(tt.mask)
		if err != nil {
			t.Errorf("MaskToPrefix(%q) error = %v", tt.mask, err)
			continue
		}
		if got != tt.want {
			t.Errorf("MaskToPrefix(%q) = %d, want %d", tt.mask, got, tt.want)
		}
	}
}

func TestPrefixToMask(t *testing.T) {
	tests := []struct {
		prefix int
		want   string
	}{
		{24, "255.255.255.0"},
		{16, "255.255.0.0"},
		{8, "255.0.0.0"},
		{32, "255.255.255.255"},
		{0, "0.0.0.0"},
	}

	for _, tt := range tests {
		got, err := PrefixToMask(tt.prefix)
		if err != nil {
			t.Errorf("PrefixToMask(%d) error = %v", tt.prefix, err)
			continue
		}
		if got != tt.want {
			t.Errorf("PrefixToMask(%d) = %q, want %q", tt.prefix, got, tt.want)
		}
	}
}

func TestIPRange(t *testing.T) {
	ips, err := IPRange("192.168.1.0/30")
	if err != nil {
		t.Fatalf("IPRange() error = %v", err)
	}

	if len(ips) != 4 {
		t.Errorf("IPRange() returned %d IPs, want 4", len(ips))
	}

	expected := []string{
		"192.168.1.0",
		"192.168.1.1",
		"192.168.1.2",
		"192.168.1.3",
	}

	for i, want := range expected {
		if ips[i] != want {
			t.Errorf("IPRange()[%d] = %q, want %q", i, ips[i], want)
		}
	}
}
