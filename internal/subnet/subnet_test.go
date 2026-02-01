package subnet

import "testing"

func TestCalculate(t *testing.T) {
	info, err := Calculate("192.168.1.0/24")
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}
	if info.NetworkAddress.String() != "192.168.1.0" {
		t.Errorf("Network = %s, want 192.168.1.0", info.NetworkAddress)
	}
	if info.BroadcastAddress.String() != "192.168.1.255" {
		t.Errorf("Broadcast = %s, want 192.168.1.255", info.BroadcastAddress)
	}
	if info.UsableHosts != 254 {
		t.Errorf("UsableHosts = %d, want 254", info.UsableHosts)
	}
}

func TestSplit(t *testing.T) {
	subnets, err := Split("192.168.1.0/24", 26)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}
	if len(subnets) != 4 {
		t.Errorf("got %d subnets, want 4", len(subnets))
	}
}

func TestContains(t *testing.T) {
	result, _ := Contains("192.168.1.0/24", "192.168.1.100")
	if !result {
		t.Error("expected true")
	}
	result, _ = Contains("192.168.1.0/24", "192.168.2.1")
	if result {
		t.Error("expected false")
	}
}

func TestOverlaps(t *testing.T) {
	result, _ := Overlaps("192.168.1.0/24", "192.168.1.128/25")
	if !result {
		t.Error("expected overlap")
	}
	result, _ = Overlaps("192.168.1.0/24", "192.168.2.0/24")
	if result {
		t.Error("expected no overlap")
	}
}

func TestListHosts(t *testing.T) {
	hosts, err := ListHosts("192.168.1.0/30", 0)
	if err != nil {
		t.Fatalf("ListHosts failed: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("got %d hosts, want 2", len(hosts))
	}
}

func TestIPRange(t *testing.T) {
	ips, err := IPRange("192.168.1.1", "192.168.1.10")
	if err != nil {
		t.Fatalf("IPRange failed: %v", err)
	}
	if len(ips) != 10 {
		t.Errorf("got %d IPs, want 10", len(ips))
	}
}

func TestMaskToCIDR(t *testing.T) {
	result, _ := MaskToCIDR("255.255.255.0")
	if result != 24 {
		t.Errorf("got %d, want 24", result)
	}
}

func TestCIDRToMask(t *testing.T) {
	result, _ := CIDRToMask(24)
	if result != "255.255.255.0" {
		t.Errorf("got %s, want 255.255.255.0", result)
	}
}

func TestIPClass(t *testing.T) {
	info, _ := Calculate("10.0.0.0/8")
	if info.IPClass != "A" {
		t.Errorf("got %s, want A", info.IPClass)
	}
}

func TestIsPrivate(t *testing.T) {
	info, _ := Calculate("192.168.1.0/24")
	if !info.IsPrivate {
		t.Error("expected private")
	}
	info, _ = Calculate("8.8.8.0/24")
	if info.IsPrivate {
		t.Error("expected public")
	}
}
