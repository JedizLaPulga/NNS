package macutil

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"},
		{"aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"},
		{"aabbccddeeff", "aa:bb:cc:dd:ee:ff"},
		{"invalid", ""},
		{"aa:bb:cc", ""},
	}

	for _, tt := range tests {
		got := Normalize(tt.input)
		if got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormat(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:ff"

	tests := []struct {
		style string
		want  string
	}{
		{"colon", "aa:bb:cc:dd:ee:ff"},
		{"dash", "aa-bb-cc-dd-ee-ff"},
		{"dot", "aabb.ccdd.eeff"},
		{"bare", "aabbccddeeff"},
		{"upper", "AA:BB:CC:DD:EE:FF"},
	}

	for _, tt := range tests {
		got := Format(mac, tt.style)
		if got != tt.want {
			t.Errorf("Format(%q, %q) = %q, want %q", mac, tt.style, got, tt.want)
		}
	}
}

func TestGenerate(t *testing.T) {
	mac1 := Generate(true)
	mac2 := Generate(true)

	// Should be valid
	if !IsValid(mac1) {
		t.Errorf("Generate() produced invalid MAC: %s", mac1)
	}

	// Should be different
	if mac1 == mac2 {
		t.Error("Generate() produced identical MACs")
	}

	// Local bit should be set
	info, _ := Parse(mac1)
	if !info.IsLocal {
		t.Error("Generate(true) should produce locally administered MAC")
	}
}

func TestGenerateWithOUI(t *testing.T) {
	oui := "00:50:56" // VMware

	mac, err := GenerateWithOUI(oui)
	if err != nil {
		t.Fatalf("GenerateWithOUI() error = %v", err)
	}

	if !strings.HasPrefix(mac, "00:50:56:") {
		t.Errorf("GenerateWithOUI() = %q, should start with %q", mac, oui+":")
	}
}

func TestParse(t *testing.T) {
	info, err := Parse("00:0c:29:aa:bb:cc")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if info.OUI != "00:0c:29" {
		t.Errorf("OUI = %q, want %q", info.OUI, "00:0c:29")
	}

	if info.Vendor != "VMware" {
		t.Errorf("Vendor = %q, want %q", info.Vendor, "VMware")
	}
}

func TestIsValid(t *testing.T) {
	tests := []struct {
		mac  string
		want bool
	}{
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA-BB-CC-DD-EE-FF", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsValid(tt.mac)
		if got != tt.want {
			t.Errorf("IsValid(%q) = %v, want %v", tt.mac, got, tt.want)
		}
	}
}

func TestIsBroadcast(t *testing.T) {
	if !IsBroadcast("ff:ff:ff:ff:ff:ff") {
		t.Error("ff:ff:ff:ff:ff:ff should be broadcast")
	}
	if IsBroadcast("aa:bb:cc:dd:ee:ff") {
		t.Error("aa:bb:cc:dd:ee:ff should not be broadcast")
	}
}

func TestIsZero(t *testing.T) {
	if !IsZero("00:00:00:00:00:00") {
		t.Error("00:00:00:00:00:00 should be zero")
	}
	if IsZero("aa:bb:cc:dd:ee:ff") {
		t.Error("aa:bb:cc:dd:ee:ff should not be zero")
	}
}

func TestCompare(t *testing.T) {
	if !Compare("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF") {
		t.Error("MACs should be equal")
	}
	if Compare("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66") {
		t.Error("MACs should not be equal")
	}
}
