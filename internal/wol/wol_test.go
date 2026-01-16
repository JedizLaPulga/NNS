package wol

import (
	"testing"
)

func TestParseMAC(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"aa:bb:cc:dd:ee:ff", false},
		{"AA:BB:CC:DD:EE:FF", false},
		{"aa-bb-cc-dd-ee-ff", false},
		{"aabbccddeeff", false},
		{"aa.bb.cc.dd.ee.ff", false},
		{"invalid", true},
		{"aa:bb:cc", true},
		{"gg:hh:ii:jj:kk:ll", true},
	}

	for _, tt := range tests {
		_, err := ParseMAC(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseMAC(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestNew(t *testing.T) {
	packet, err := New("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	bytes := packet.Bytes()

	// Check length (6 header + 96 payload = 102)
	if len(bytes) != 102 {
		t.Errorf("Packet length = %d, want 102", len(bytes))
	}

	// Check header (first 6 bytes should be 0xFF)
	for i := 0; i < 6; i++ {
		if bytes[i] != 0xFF {
			t.Errorf("Header byte %d = %x, want 0xFF", i, bytes[i])
		}
	}

	// Check first MAC in payload
	expectedMAC := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := 0; i < 6; i++ {
		if bytes[6+i] != expectedMAC[i] {
			t.Errorf("Payload byte %d = %x, want %x", i, bytes[6+i], expectedMAC[i])
		}
	}
}

func TestFormatMAC(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aabbccddeeff", "aa:bb:cc:dd:ee:ff"},
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"},
	}

	for _, tt := range tests {
		got := FormatMAC(tt.input)
		if got != tt.want {
			t.Errorf("FormatMAC(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMagicPacketBytes(t *testing.T) {
	packet, _ := New("00:11:22:33:44:55")
	bytes := packet.Bytes()

	// Verify 16 repetitions of MAC
	mac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	for i := 0; i < 16; i++ {
		offset := 6 + i*6
		for j := 0; j < 6; j++ {
			if bytes[offset+j] != mac[j] {
				t.Errorf("MAC repetition %d, byte %d = %x, want %x",
					i, j, bytes[offset+j], mac[j])
			}
		}
	}
}
