package wakewait

import (
	"net"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.WolPort != 9 {
		t.Errorf("WolPort = %d, want 9", cfg.WolPort)
	}
	if cfg.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", cfg.Timeout)
	}
	if cfg.CheckInterval != 2*time.Second {
		t.Errorf("CheckInterval = %v, want 2s", cfg.CheckInterval)
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient(DefaultConfig())
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
}

func TestCreateMagicPacket(t *testing.T) {
	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	packet := createMagicPacket(mac)

	if len(packet) != 102 {
		t.Errorf("packet length = %d, want 102", len(packet))
	}

	// Check sync stream (6 bytes of 0xFF)
	for i := 0; i < 6; i++ {
		if packet[i] != 0xFF {
			t.Errorf("sync byte %d = 0x%02X, want 0xFF", i, packet[i])
		}
	}

	// Check MAC is repeated 16 times
	for i := 0; i < 16; i++ {
		offset := 6 + i*6
		for j := 0; j < 6; j++ {
			if packet[offset+j] != mac[j] {
				t.Errorf("MAC byte at offset %d = 0x%02X, want 0x%02X",
					offset+j, packet[offset+j], mac[j])
			}
		}
	}
}

func TestParseMAC(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA-BB-CC-DD-EE-FF", true},
		{"invalid", false},
		{"", false},
		{"AA:BB:CC:DD:EE", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := ParseMAC(tt.input)
			if tt.valid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestResultStatus(t *testing.T) {
	tests := []Status{StatusPending, StatusWaking, StatusOnline, StatusTimeout, StatusError}

	for _, s := range tests {
		if s == "" {
			t.Errorf("status should not be empty")
		}
	}
}

func TestOnEvent(t *testing.T) {
	client := NewClient(DefaultConfig())
	var called bool

	client.OnEvent(func(r Result) {
		called = true
	})

	// Trigger notification with test result
	client.notify(Result{Status: StatusPending})

	if !called {
		t.Error("event callback was not called")
	}
}

func TestQuickWakeInvalidMAC(t *testing.T) {
	err := QuickWake("invalid", "")
	if err == nil {
		t.Error("expected error for invalid MAC")
	}
}
