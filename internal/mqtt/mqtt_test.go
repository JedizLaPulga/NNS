package mqtt

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Port != 1883 {
		t.Errorf("expected port 1883, got %d", opts.Port)
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", opts.Timeout)
	}
	if opts.PingCount != 5 {
		t.Errorf("expected PingCount 5, got %d", opts.PingCount)
	}
	if opts.ClientID != "nns-mqtt-check" {
		t.Errorf("expected clientID 'nns-mqtt-check', got '%s'", opts.ClientID)
	}
	if len(opts.Topics) != 3 {
		t.Errorf("expected 3 default topics, got %d", len(opts.Topics))
	}
}

func TestNewChecker(t *testing.T) {
	opts := Options{Host: "test.mosquitto.org"}
	checker := NewChecker(opts)

	if checker.opts.Timeout != 10*time.Second {
		t.Errorf("expected default timeout, got %v", checker.opts.Timeout)
	}
	if checker.opts.PingCount != 5 {
		t.Errorf("expected default PingCount, got %d", checker.opts.PingCount)
	}
	if checker.opts.ClientID != "nns-mqtt-check" {
		t.Errorf("expected default clientID, got '%s'", checker.opts.ClientID)
	}
	if checker.opts.Port != 1883 {
		t.Errorf("expected default port 1883, got %d", checker.opts.Port)
	}
}

func TestNewCheckerWithOpts(t *testing.T) {
	opts := Options{
		Host:      "broker.example.com",
		Port:      8883,
		Timeout:   5 * time.Second,
		PingCount: 3,
		ClientID:  "custom-client",
	}
	checker := NewChecker(opts)

	if checker.opts.Port != 8883 {
		t.Errorf("expected port 8883, got %d", checker.opts.Port)
	}
	if checker.opts.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", checker.opts.Timeout)
	}
	if checker.opts.PingCount != 3 {
		t.Errorf("expected PingCount 3, got %d", checker.opts.PingCount)
	}
	if checker.opts.ClientID != "custom-client" {
		t.Errorf("expected clientID 'custom-client', got '%s'", checker.opts.ClientID)
	}
}

func TestEncodeString(t *testing.T) {
	tests := []struct {
		input    string
		wantLen  int
		wantHigh byte
		wantLow  byte
	}{
		{"", 2, 0, 0},
		{"A", 3, 0, 1},
		{"MQTT", 6, 0, 4},
		{"hello world", 13, 0, 11},
	}

	for _, tt := range tests {
		encoded := encodeString(tt.input)
		if len(encoded) != tt.wantLen {
			t.Errorf("encodeString(%q): len=%d, want %d", tt.input, len(encoded), tt.wantLen)
		}
		if encoded[0] != tt.wantHigh || encoded[1] != tt.wantLow {
			t.Errorf("encodeString(%q): length bytes [%d,%d], want [%d,%d]",
				tt.input, encoded[0], encoded[1], tt.wantHigh, tt.wantLow)
		}
	}
}

func TestEncodeRemainingLength(t *testing.T) {
	tests := []struct {
		length int
		want   []byte
	}{
		{0, []byte{0}},
		{127, []byte{127}},
		{128, []byte{0x80, 0x01}},
		{16383, []byte{0xFF, 0x7F}},
	}

	for _, tt := range tests {
		got := encodeRemainingLength(tt.length)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("encodeRemainingLength(%d) = %v, want %v", tt.length, got, tt.want)
		}
	}
}

func TestDecodeRemainingLength(t *testing.T) {
	tests := []struct {
		input []byte
		want  int
	}{
		{[]byte{0}, 0},
		{[]byte{127}, 127},
		{[]byte{0x80, 0x01}, 128},
		{[]byte{0xFF, 0x7F}, 16383},
	}

	for _, tt := range tests {
		reader := bufio.NewReader(bytes.NewReader(tt.input))
		got, err := decodeRemainingLength(reader)
		if err != nil {
			t.Errorf("decodeRemainingLength(%v): unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("decodeRemainingLength(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestConnackMessage(t *testing.T) {
	tests := []struct {
		code byte
		want string
	}{
		{connAccepted, "Connection Accepted"},
		{connRefusedProtocol, "Connection Refused: unacceptable protocol version"},
		{connRefusedIdentifier, "Connection Refused: identifier rejected"},
		{connRefusedUnavail, "Connection Refused: server unavailable"},
		{connRefusedBadAuth, "Connection Refused: bad username or password"},
		{connRefusedNotAuth, "Connection Refused: not authorized"},
		{99, "Unknown return code: 99"},
	}

	for _, tt := range tests {
		got := connackMessage(tt.code)
		if got != tt.want {
			t.Errorf("connackMessage(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestBuildConnectPacket(t *testing.T) {
	pkt := buildConnectPacket("test-client", "", "")

	// First byte: CONNECT type (1 << 4 = 0x10)
	if pkt[0] != 0x10 {
		t.Errorf("expected first byte 0x10, got 0x%02x", pkt[0])
	}

	// Payload should contain "MQTT" protocol name
	found := false
	for i := 0; i < len(pkt)-3; i++ {
		if pkt[i] == 'M' && pkt[i+1] == 'Q' && pkt[i+2] == 'T' && pkt[i+3] == 'T' {
			found = true
			break
		}
	}
	if !found {
		t.Error("CONNECT packet missing 'MQTT' protocol name")
	}
}

func TestBuildConnectPacketWithAuth(t *testing.T) {
	pkt := buildConnectPacket("test", "user", "pass")

	// Should be longer than unauthenticated version
	pktNoAuth := buildConnectPacket("test", "", "")
	if len(pkt) <= len(pktNoAuth) {
		t.Error("authenticated packet should be longer than unauthenticated")
	}
}

func TestBuildSubscribePacket(t *testing.T) {
	pkt := buildSubscribePacket(1, "test/topic", 0)

	// First byte: SUBSCRIBE type with reserved bits
	expectedType := (packetSUBSCRIBE | 0x02) << 4
	if pkt[0] != expectedType {
		t.Errorf("expected first byte 0x%02x, got 0x%02x", expectedType, pkt[0])
	}

	if len(pkt) < 5 {
		t.Error("SUBSCRIBE packet too short")
	}
}

func TestBuildUnsubscribePacket(t *testing.T) {
	pkt := buildUnsubscribePacket(1, "test/topic")

	expectedType := (packetUNSUBSCRIBE | 0x02) << 4
	if pkt[0] != expectedType {
		t.Errorf("expected first byte 0x%02x, got 0x%02x", expectedType, pkt[0])
	}
}

func TestCalculatePingStats(t *testing.T) {
	stats := &PingStats{
		AllRTTs: []time.Duration{
			10 * time.Millisecond,
			20 * time.Millisecond,
			15 * time.Millisecond,
			25 * time.Millisecond,
			30 * time.Millisecond,
		},
	}

	calculatePingStats(stats)

	if stats.MinRTT != 10*time.Millisecond {
		t.Errorf("expected MinRTT 10ms, got %v", stats.MinRTT)
	}
	if stats.MaxRTT != 30*time.Millisecond {
		t.Errorf("expected MaxRTT 30ms, got %v", stats.MaxRTT)
	}
	if stats.AvgRTT != 20*time.Millisecond {
		t.Errorf("expected AvgRTT 20ms, got %v", stats.AvgRTT)
	}
	if stats.StdDev <= 0 {
		t.Error("expected positive StdDev")
	}
}

func TestResultFormat(t *testing.T) {
	result := &Result{
		Host:      "test.mosquitto.org",
		Port:      1883,
		Connected: true,
		ConnTime:  5 * time.Millisecond,
		Duration:  100 * time.Millisecond,
		AuthResult: AuthResult{
			Tested:        true,
			AnonAllowed:   true,
			ReturnCode:    connAccepted,
			ReturnMessage: "Connection Accepted",
		},
		PingLatency: PingStats{
			Count:    3,
			Sent:     3,
			Received: 3,
			MinRTT:   5 * time.Millisecond,
			AvgRTT:   10 * time.Millisecond,
			MaxRTT:   15 * time.Millisecond,
			StdDev:   3 * time.Millisecond,
		},
		Topics: []TopicResult{
			{Filter: "$SYS/#", Subscribed: true, QoS: 0},
			{Filter: "#", Subscribed: true, QoS: 0},
		},
	}

	output := result.Format()

	if len(output) == 0 {
		t.Error("expected non-empty formatted output")
	}
	if !bytes.Contains([]byte(output), []byte("test.mosquitto.org")) {
		t.Error("format should contain hostname")
	}
	if !bytes.Contains([]byte(output), []byte("Anonymous")) {
		t.Error("format should mention anonymous access")
	}
	if !bytes.Contains([]byte(output), []byte("PING")) {
		t.Error("format should contain PING section")
	}
}

func TestResultFormatCompact(t *testing.T) {
	result := &Result{
		Host:      "broker.test",
		Port:      1883,
		Connected: true,
		AuthResult: AuthResult{
			AnonAllowed: true,
		},
		PingLatency: PingStats{
			AvgRTT: 5 * time.Millisecond,
		},
	}

	compact := result.FormatCompact()
	if len(compact) == 0 {
		t.Error("expected non-empty compact output")
	}
	if !bytes.Contains([]byte(compact), []byte("broker.test")) {
		t.Error("compact format should contain hostname")
	}
}

func TestResultFormatCompactFailed(t *testing.T) {
	result := &Result{
		Host:      "dead.broker",
		Port:      1883,
		Connected: false,
	}

	compact := result.FormatCompact()
	if !bytes.Contains([]byte(compact), []byte("connection failed")) {
		t.Error("compact format for failed connection should say 'connection failed'")
	}
}

// TestCheckConnectionRefused tests behavior when no broker is running.
func TestCheckConnectionRefused(t *testing.T) {
	// Use a port that's unlikely to have an MQTT broker
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close() // Close immediately so connection will be refused

	opts := Options{
		Host:      "127.0.0.1",
		Port:      port,
		Timeout:   2 * time.Second,
		PingCount: 1,
	}
	checker := NewChecker(opts)

	result, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check should not return error, got: %v", err)
	}

	if result.Connected {
		t.Error("expected Connected=false for refused connection")
	}
	if result.Error == nil {
		t.Error("expected Error to be set")
	}
}

// TestCheckWithMockBroker tests with a mock MQTT broker.
func TestCheckWithMockBroker(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock broker: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Mock broker: accept connection, respond to CONNECT with CONNACK
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleMockClient(conn)
		}
	}()

	opts := Options{
		Host:      "127.0.0.1",
		Port:      port,
		Timeout:   3 * time.Second,
		PingCount: 2,
		ClientID:  "test-check",
		Topics:    []string{"test/topic"},
	}
	checker := NewChecker(opts)

	result, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	if !result.Connected {
		t.Errorf("expected Connected=true, error: %v", result.Error)
	}
	if !result.AuthResult.AnonAllowed {
		t.Error("expected anonymous access to be allowed")
	}
	if result.ConnTime < 0 {
		t.Error("expected non-negative ConnTime")
	}
}

func handleMockClient(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		pktType, _, err := readPacket(reader)
		if err != nil {
			return
		}

		switch pktType {
		case packetCONNECT:
			// Send CONNACK (accepted)
			connack := []byte{packetCONNACK << 4, 2, 0, 0}
			conn.Write(connack)
		case packetPINGREQ:
			// Send PINGRESP
			pingresp := []byte{packetPINGRESP << 4, 0}
			conn.Write(pingresp)
		case packetSUBSCRIBE:
			// Send SUBACK with QoS 0 granted
			suback := []byte{packetSUBACK << 4, 3, 0, 1, 0}
			conn.Write(suback)
		case packetUNSUBSCRIBE:
			// Ignore
		case packetDISCONNECT:
			return
		}
	}
}

func TestReadPacket(t *testing.T) {
	// CONNACK packet: type=2, remaining=2, payload=[0,0]
	data := []byte{packetCONNACK << 4, 2, 0, 0}
	reader := bufio.NewReader(bytes.NewReader(data))

	pktType, payload, err := readPacket(reader)
	if err != nil {
		t.Fatalf("readPacket error: %v", err)
	}
	if pktType != packetCONNACK {
		t.Errorf("expected packet type %d, got %d", packetCONNACK, pktType)
	}
	if len(payload) != 2 {
		t.Errorf("expected payload length 2, got %d", len(payload))
	}
}

func TestWrapPacket(t *testing.T) {
	payload := []byte{0x01, 0x02}
	pkt := wrapPacket(packetPINGREQ, payload)

	if pkt[0] != packetPINGREQ<<4 {
		t.Errorf("expected first byte 0x%02x, got 0x%02x", packetPINGREQ<<4, pkt[0])
	}
	if pkt[1] != 2 {
		t.Errorf("expected remaining length 2, got %d", pkt[1])
	}
}
