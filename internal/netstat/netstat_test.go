package netstat

import (
	"testing"
)

func TestParseAddress(t *testing.T) {
	tests := []struct {
		input    string
		wantAddr string
		wantPort int
	}{
		{"192.168.1.1:80", "192.168.1.1", 80},
		{"0.0.0.0:443", "0.0.0.0", 443},
		{"*:22", "0.0.0.0", 22},
		{"[::]:80", "::", 80},
		{"127.0.0.1:8080", "127.0.0.1", 8080},
	}

	for _, tt := range tests {
		addr, port := parseAddress(tt.input)
		if addr != tt.wantAddr || port != tt.wantPort {
			t.Errorf("parseAddress(%q) = (%q, %d), want (%q, %d)",
				tt.input, addr, port, tt.wantAddr, tt.wantPort)
		}
	}
}

func TestFilterByProtocol(t *testing.T) {
	conns := []Connection{
		{Protocol: "tcp", LocalPort: 80},
		{Protocol: "udp", LocalPort: 53},
		{Protocol: "tcp6", LocalPort: 443},
	}

	tcp := FilterByProtocol(conns, "tcp")
	if len(tcp) != 2 {
		t.Errorf("FilterByProtocol(tcp) = %d connections, want 2", len(tcp))
	}

	udp := FilterByProtocol(conns, "udp")
	if len(udp) != 1 {
		t.Errorf("FilterByProtocol(udp) = %d connections, want 1", len(udp))
	}
}

func TestFilterByState(t *testing.T) {
	conns := []Connection{
		{Protocol: "tcp", State: "LISTEN"},
		{Protocol: "tcp", State: "ESTABLISHED"},
		{Protocol: "tcp", State: "LISTEN"},
	}

	listening := FilterByState(conns, "LISTEN")
	if len(listening) != 2 {
		t.Errorf("FilterByState(LISTEN) = %d, want 2", len(listening))
	}
}

func TestGetListening(t *testing.T) {
	conns := []Connection{
		{State: "LISTEN"},
		{State: "ESTABLISHED"},
		{State: "TIME_WAIT"},
	}

	listening := GetListening(conns)
	if len(listening) != 1 {
		t.Errorf("GetListening() = %d, want 1", len(listening))
	}
}

func TestGetEstablished(t *testing.T) {
	conns := []Connection{
		{State: "LISTEN"},
		{State: "ESTABLISHED"},
		{State: "ESTABLISHED"},
	}

	established := GetEstablished(conns)
	if len(established) != 2 {
		t.Errorf("GetEstablished() = %d, want 2", len(established))
	}
}

func TestParseWindowsNetstat(t *testing.T) {
	output := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       1234
  TCP    192.168.1.1:52341      93.184.216.34:443      ESTABLISHED     5678
  UDP    0.0.0.0:53             *:*                                    1111
`
	conns, err := parseWindowsNetstat(output)
	if err != nil {
		t.Fatalf("parseWindowsNetstat() error = %v", err)
	}
	if len(conns) != 3 {
		t.Errorf("parseWindowsNetstat() = %d connections, want 3", len(conns))
	}
}

func TestParseLinuxSS(t *testing.T) {
	output := `Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port
tcp    LISTEN  0       128      0.0.0.0:22            0.0.0.0:*
tcp    ESTAB   0       0        192.168.1.1:22       192.168.1.2:54321
`
	conns, err := parseLinuxSS(output)
	if err != nil {
		t.Fatalf("parseLinuxSS() error = %v", err)
	}
	if len(conns) != 2 {
		t.Errorf("parseLinuxSS() = %d connections, want 2", len(conns))
	}
}

func TestParseWindowsRoute(t *testing.T) {
	output := `
===========================================================================
Interface List
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
      192.168.1.0    255.255.255.0         On-link    192.168.1.100    281
===========================================================================
`
	entries, err := parseWindowsRoute(output)
	if err != nil {
		t.Fatalf("parseWindowsRoute() error = %v", err)
	}
	if len(entries) < 1 {
		t.Error("parseWindowsRoute() should return at least 1 entry")
	}
}

func TestParseLinuxIPRoute(t *testing.T) {
	output := `default via 192.168.1.1 dev eth0 metric 100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
`
	entries, err := parseLinuxIPRoute(output)
	if err != nil {
		t.Fatalf("parseLinuxIPRoute() error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("parseLinuxIPRoute() = %d entries, want 2", len(entries))
	}
}
