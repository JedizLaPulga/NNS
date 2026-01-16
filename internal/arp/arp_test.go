package arp

import (
	"testing"
)

func TestNormalizeMACAddress(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"},
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"(incomplete)", ""},
		{"invalid", ""},
	}

	for _, tt := range tests {
		got := normalizeMACAddress(tt.input)
		if got != tt.want {
			t.Errorf("normalizeMACAddress(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLookupVendor(t *testing.T) {
	tests := []struct {
		mac  string
		want string
	}{
		{"00:0c:29:aa:bb:cc", "VMware"},
		{"00-0c-29-aa-bb-cc", "VMware"},
		{"b8:27:eb:11:22:33", "Raspberry Pi"},
		{"00:00:00:00:00:00", ""},
		{"invalid", ""},
	}

	for _, tt := range tests {
		got := LookupVendor(tt.mac)
		if got != tt.want {
			t.Errorf("LookupVendor(%q) = %q, want %q", tt.mac, got, tt.want)
		}
	}
}

func TestFilterByInterface(t *testing.T) {
	entries := []Entry{
		{IP: "192.168.1.1", Interface: "eth0"},
		{IP: "192.168.1.2", Interface: "wlan0"},
		{IP: "192.168.1.3", Interface: "eth0"},
	}

	filtered := FilterByInterface(entries, "eth0")
	if len(filtered) != 2 {
		t.Errorf("FilterByInterface() returned %d entries, want 2", len(filtered))
	}
}

func TestGetInterfaces(t *testing.T) {
	entries := []Entry{
		{IP: "192.168.1.1", Interface: "eth0"},
		{IP: "192.168.1.2", Interface: "wlan0"},
		{IP: "192.168.1.3", Interface: "eth0"},
	}

	ifaces := GetInterfaces(entries)
	if len(ifaces) != 2 {
		t.Errorf("GetInterfaces() returned %d interfaces, want 2", len(ifaces))
	}
}

func TestParseWindowsARP(t *testing.T) {
	output := `
Interface: 192.168.1.100 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.2           11-22-33-44-55-66     static
`
	entries, err := parseWindowsARP(output)
	if err != nil {
		t.Fatalf("parseWindowsARP() error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("parseWindowsARP() returned %d entries, want 2", len(entries))
	}
	if entries[0].IP != "192.168.1.1" {
		t.Errorf("First entry IP = %s, want 192.168.1.1", entries[0].IP)
	}
	if entries[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("First entry MAC = %s, want aa:bb:cc:dd:ee:ff", entries[0].MAC)
	}
}

func TestParseLinuxProcARP(t *testing.T) {
	output := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0
`
	entries, err := parseLinuxProcARP(output)
	if err != nil {
		t.Fatalf("parseLinuxProcARP() error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("parseLinuxProcARP() returned %d entries, want 2", len(entries))
	}
}

func TestParseDarwinARP(t *testing.T) {
	output := `? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (192.168.1.2) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
`
	entries, err := parseDarwinARP(output)
	if err != nil {
		t.Fatalf("parseDarwinARP() error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("parseDarwinARP() returned %d entries, want 2", len(entries))
	}
}
