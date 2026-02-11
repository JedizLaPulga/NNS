// Package mqtt provides MQTT broker connectivity testing and analysis.
package mqtt

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// MQTT packet types
const (
	packetCONNECT     byte = 1
	packetCONNACK     byte = 2
	packetPUBLISH     byte = 3
	packetPUBACK      byte = 4
	packetSUBSCRIBE   byte = 8
	packetSUBACK      byte = 9
	packetUNSUBSCRIBE byte = 10
	packetPINGREQ     byte = 12
	packetPINGRESP    byte = 13
	packetDISCONNECT  byte = 14
)

// MQTT CONNACK return codes
const (
	connAccepted          byte = 0
	connRefusedProtocol   byte = 1
	connRefusedIdentifier byte = 2
	connRefusedUnavail    byte = 3
	connRefusedBadAuth    byte = 4
	connRefusedNotAuth    byte = 5
)

// Result holds the outcome of a broker check.
type Result struct {
	Host        string
	Port        int
	Connected   bool
	UseTLS      bool
	Error       error
	ConnTime    time.Duration
	TLSTime     time.Duration
	AuthResult  AuthResult
	PingLatency PingStats
	Topics      []TopicResult
	BrokerInfo  BrokerInfo
	StartTime   time.Time
	Duration    time.Duration
}

// AuthResult describes authentication test results.
type AuthResult struct {
	Tested        bool
	AnonAllowed   bool
	AuthRequired  bool
	AuthSuccess   bool
	ReturnCode    byte
	ReturnMessage string
}

// PingStats holds MQTT PINGREQ/PINGRESP latency statistics.
type PingStats struct {
	Count    int
	Sent     int
	Received int
	MinRTT   time.Duration
	MaxRTT   time.Duration
	AvgRTT   time.Duration
	StdDev   time.Duration
	AllRTTs  []time.Duration
}

// TopicResult holds a topic subscription probe result.
type TopicResult struct {
	Filter     string
	Subscribed bool
	QoS        byte
	Error      error
}

// BrokerInfo captures information about the MQTT broker.
type BrokerInfo struct {
	ProtocolLevel byte
	CleanSession  bool
	KeepAlive     uint16
	MaxTopicAlias int
	ServerID      string
}

// Options configures the MQTT checker.
type Options struct {
	Host       string
	Port       int
	UseTLS     bool
	SkipVerify bool
	Username   string
	Password   string
	ClientID   string
	Timeout    time.Duration
	PingCount  int
	Topics     []string // Topic filters to probe
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Port:      1883,
		Timeout:   10 * time.Second,
		PingCount: 5,
		ClientID:  "nns-mqtt-check",
		Topics: []string{
			"$SYS/#",
			"#",
			"test/nns",
		},
	}
}

// Checker performs MQTT broker checks.
type Checker struct {
	opts Options
}

// NewChecker creates a new MQTT checker.
func NewChecker(opts Options) *Checker {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.PingCount <= 0 {
		opts.PingCount = 5
	}
	if opts.ClientID == "" {
		opts.ClientID = "nns-mqtt-check"
	}
	if opts.Port <= 0 {
		opts.Port = 1883
	}
	return &Checker{opts: opts}
}

// Check performs a full MQTT broker analysis.
func (c *Checker) Check(ctx context.Context) (*Result, error) {
	start := time.Now()
	result := &Result{
		Host:      c.opts.Host,
		Port:      c.opts.Port,
		UseTLS:    c.opts.UseTLS,
		StartTime: start,
	}

	conn, err := c.connect(ctx, result)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result, nil
	}
	defer conn.Close()

	result.Connected = true

	// Test MQTT CONNECT
	authResult, err := c.mqttConnect(conn, result)
	result.AuthResult = authResult
	if err != nil {
		result.Error = fmt.Errorf("MQTT CONNECT failed: %w", err)
		result.Duration = time.Since(start)
		return result, nil
	}

	// Ping latency
	if result.AuthResult.AnonAllowed || result.AuthResult.AuthSuccess {
		result.PingLatency = c.measurePingLatency(conn)
	}

	// Topic probing
	if (result.AuthResult.AnonAllowed || result.AuthResult.AuthSuccess) && len(c.opts.Topics) > 0 {
		result.Topics = c.probeTopics(conn)
	}

	// Disconnect cleanly
	c.mqttDisconnect(conn)

	result.Duration = time.Since(start)
	return result, nil
}

// connect establishes a TCP (optionally TLS) connection.
func (c *Checker) connect(ctx context.Context, result *Result) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", c.opts.Host, c.opts.Port)

	dialer := &net.Dialer{Timeout: c.opts.Timeout}
	connStart := time.Now()

	var conn net.Conn
	var err error

	if c.opts.UseTLS {
		tlsConfig := &tls.Config{
			ServerName:         c.opts.Host,
			InsecureSkipVerify: c.opts.SkipVerify,
		}
		tcpConn, tcpErr := dialer.DialContext(ctx, "tcp", addr)
		if tcpErr != nil {
			return nil, fmt.Errorf("TCP connection failed: %w", tcpErr)
		}
		result.ConnTime = time.Since(connStart)

		tlsStart := time.Now()
		tlsConn := tls.Client(tcpConn, tlsConfig)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		result.TLSTime = time.Since(tlsStart)
		conn = tlsConn
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("TCP connection failed: %w", err)
		}
		result.ConnTime = time.Since(connStart)
	}

	return conn, nil
}

// mqttConnect sends a CONNECT packet and reads the CONNACK.
func (c *Checker) mqttConnect(conn net.Conn, result *Result) (AuthResult, error) {
	auth := AuthResult{Tested: true}

	pkt := buildConnectPacket(c.opts.ClientID, c.opts.Username, c.opts.Password)
	conn.SetWriteDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := conn.Write(pkt); err != nil {
		return auth, fmt.Errorf("failed to send CONNECT: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(c.opts.Timeout))
	reader := bufio.NewReader(conn)

	pktType, payload, err := readPacket(reader)
	if err != nil {
		return auth, fmt.Errorf("failed to read CONNACK: %w", err)
	}

	if pktType != packetCONNACK {
		return auth, fmt.Errorf("expected CONNACK, got packet type %d", pktType)
	}

	if len(payload) < 2 {
		return auth, fmt.Errorf("CONNACK too short")
	}

	returnCode := payload[1]
	auth.ReturnCode = returnCode
	auth.ReturnMessage = connackMessage(returnCode)

	switch returnCode {
	case connAccepted:
		if c.opts.Username == "" {
			auth.AnonAllowed = true
		} else {
			auth.AuthSuccess = true
		}
	case connRefusedBadAuth, connRefusedNotAuth:
		auth.AuthRequired = true
	}

	result.BrokerInfo = BrokerInfo{
		ProtocolLevel: 4, // MQTT 3.1.1
		CleanSession:  true,
		KeepAlive:     60,
	}

	return auth, nil
}

// measurePingLatency sends PINGREQ packets and measures PINGRESP times.
func (c *Checker) measurePingLatency(conn net.Conn) PingStats {
	stats := PingStats{
		AllRTTs: make([]time.Duration, 0, c.opts.PingCount),
	}

	for i := 0; i < c.opts.PingCount; i++ {
		stats.Sent++

		pingReq := []byte{packetPINGREQ << 4, 0}
		conn.SetWriteDeadline(time.Now().Add(c.opts.Timeout))
		start := time.Now()

		if _, err := conn.Write(pingReq); err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(c.opts.Timeout))
		reader := bufio.NewReader(conn)
		pktType, _, err := readPacket(reader)
		rtt := time.Since(start)

		if err != nil || pktType != packetPINGRESP {
			continue
		}

		stats.Received++
		stats.AllRTTs = append(stats.AllRTTs, rtt)
		stats.Count++

		if i < c.opts.PingCount-1 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	if len(stats.AllRTTs) > 0 {
		calculatePingStats(&stats)
	}

	return stats
}

// probeTopics attempts to subscribe to topic filters.
func (c *Checker) probeTopics(conn net.Conn) []TopicResult {
	results := make([]TopicResult, 0, len(c.opts.Topics))

	for i, topic := range c.opts.Topics {
		result := TopicResult{Filter: topic}

		packetID := uint16(i + 1)
		pkt := buildSubscribePacket(packetID, topic, 0)

		conn.SetWriteDeadline(time.Now().Add(c.opts.Timeout))
		if _, err := conn.Write(pkt); err != nil {
			result.Error = err
			results = append(results, result)
			continue
		}

		conn.SetReadDeadline(time.Now().Add(c.opts.Timeout))
		reader := bufio.NewReader(conn)
		pktType, payload, err := readPacket(reader)

		if err != nil {
			result.Error = err
			results = append(results, result)
			continue
		}

		if pktType == packetSUBACK && len(payload) >= 3 {
			grantedQoS := payload[2]
			if grantedQoS <= 2 {
				result.Subscribed = true
				result.QoS = grantedQoS
			}
		}

		// Unsubscribe
		unsub := buildUnsubscribePacket(packetID, topic)
		conn.SetWriteDeadline(time.Now().Add(c.opts.Timeout))
		conn.Write(unsub)

		results = append(results, result)
	}

	return results
}

func (c *Checker) mqttDisconnect(conn net.Conn) {
	pkt := []byte{packetDISCONNECT << 4, 0}
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(pkt)
}

// --- Packet builders ---

func buildConnectPacket(clientID, username, password string) []byte {
	var payload []byte

	// Protocol name "MQTT"
	payload = append(payload, 0, 4, 'M', 'Q', 'T', 'T')
	// Protocol level 4 (MQTT 3.1.1)
	payload = append(payload, 4)

	// Connect flags
	flags := byte(0x02) // Clean session
	if username != "" {
		flags |= 0x80 // Username flag
		if password != "" {
			flags |= 0x40 // Password flag
		}
	}
	payload = append(payload, flags)

	// Keep alive (60 seconds)
	payload = append(payload, 0, 60)

	// Client ID
	payload = append(payload, encodeString(clientID)...)

	// Username & password
	if username != "" {
		payload = append(payload, encodeString(username)...)
		if password != "" {
			payload = append(payload, encodeString(password)...)
		}
	}

	return wrapPacket(packetCONNECT, payload)
}

func buildSubscribePacket(packetID uint16, topic string, qos byte) []byte {
	var payload []byte
	// Packet ID
	payload = append(payload, byte(packetID>>8), byte(packetID&0xFF))
	// Topic filter + QoS
	payload = append(payload, encodeString(topic)...)
	payload = append(payload, qos)

	return wrapPacket(packetSUBSCRIBE|0x02, payload) // SUBSCRIBE has reserved bits set
}

func buildUnsubscribePacket(packetID uint16, topic string) []byte {
	var payload []byte
	payload = append(payload, byte(packetID>>8), byte(packetID&0xFF))
	payload = append(payload, encodeString(topic)...)

	return wrapPacket(packetUNSUBSCRIBE|0x02, payload)
}

func encodeString(s string) []byte {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	copy(b[2:], s)
	return b
}

func wrapPacket(typeByte byte, payload []byte) []byte {
	header := []byte{typeByte << 4}
	header = append(header, encodeRemainingLength(len(payload))...)
	return append(header, payload...)
}

func encodeRemainingLength(length int) []byte {
	var encoded []byte
	for {
		b := byte(length % 128)
		length /= 128
		if length > 0 {
			b |= 0x80
		}
		encoded = append(encoded, b)
		if length == 0 {
			break
		}
	}
	return encoded
}

func readPacket(reader *bufio.Reader) (byte, []byte, error) {
	firstByte, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}

	pktType := firstByte >> 4

	// Decode remaining length
	remaining, err := decodeRemainingLength(reader)
	if err != nil {
		return pktType, nil, err
	}

	payload := make([]byte, remaining)
	if remaining > 0 {
		if _, err := io.ReadFull(reader, payload); err != nil {
			return pktType, nil, err
		}
	}

	return pktType, payload, nil
}

func decodeRemainingLength(reader *bufio.Reader) (int, error) {
	multiplier := 1
	value := 0
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(b&0x7F) * multiplier
		if b&0x80 == 0 {
			break
		}
		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, fmt.Errorf("malformed remaining length")
		}
	}
	return value, nil
}

func connackMessage(code byte) string {
	switch code {
	case connAccepted:
		return "Connection Accepted"
	case connRefusedProtocol:
		return "Connection Refused: unacceptable protocol version"
	case connRefusedIdentifier:
		return "Connection Refused: identifier rejected"
	case connRefusedUnavail:
		return "Connection Refused: server unavailable"
	case connRefusedBadAuth:
		return "Connection Refused: bad username or password"
	case connRefusedNotAuth:
		return "Connection Refused: not authorized"
	default:
		return fmt.Sprintf("Unknown return code: %d", code)
	}
}

func calculatePingStats(stats *PingStats) {
	sorted := make([]time.Duration, len(stats.AllRTTs))
	copy(sorted, stats.AllRTTs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	stats.MinRTT = sorted[0]
	stats.MaxRTT = sorted[len(sorted)-1]

	var sum time.Duration
	for _, rtt := range sorted {
		sum += rtt
	}
	stats.AvgRTT = sum / time.Duration(len(sorted))

	var variance float64
	avgNs := float64(stats.AvgRTT.Nanoseconds())
	for _, rtt := range sorted {
		diff := float64(rtt.Nanoseconds()) - avgNs
		variance += diff * diff
	}
	variance /= float64(len(sorted))
	stats.StdDev = time.Duration(math.Sqrt(variance))
}

// Format returns formatted results.
func (r *Result) Format() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\nMQTT Broker Check: %s:%d\n", r.Host, r.Port))
	sb.WriteString(strings.Repeat("═", 60) + "\n\n")

	if r.Error != nil && !r.Connected {
		sb.WriteString(fmt.Sprintf("✗ Connection failed: %v\n", r.Error))
		return sb.String()
	}

	// Connection info
	sb.WriteString("Connection:\n")
	sb.WriteString(fmt.Sprintf("  Status:    ✓ Connected\n"))
	sb.WriteString(fmt.Sprintf("  TCP Time:  %v\n", r.ConnTime.Round(time.Microsecond)))
	if r.UseTLS {
		sb.WriteString(fmt.Sprintf("  TLS Time:  %v\n", r.TLSTime.Round(time.Microsecond)))
		sb.WriteString("  Encryption: TLS\n")
	} else {
		sb.WriteString("  Encryption: None (plaintext)\n")
	}

	// Authentication
	sb.WriteString("\nAuthentication:\n")
	if r.AuthResult.AnonAllowed {
		sb.WriteString("  ⚠ Anonymous access ALLOWED\n")
	} else if r.AuthResult.AuthRequired {
		sb.WriteString("  ✓ Authentication required\n")
	}
	if r.AuthResult.AuthSuccess {
		sb.WriteString("  ✓ Credentials accepted\n")
	}
	sb.WriteString(fmt.Sprintf("  Response:  %s\n", r.AuthResult.ReturnMessage))

	// Ping latency
	if r.PingLatency.Count > 0 {
		sb.WriteString("\nPING Latency:\n")
		sb.WriteString(fmt.Sprintf("  Sent:     %d\n", r.PingLatency.Sent))
		sb.WriteString(fmt.Sprintf("  Received: %d\n", r.PingLatency.Received))
		sb.WriteString(fmt.Sprintf("  Min RTT:  %v\n", r.PingLatency.MinRTT.Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("  Avg RTT:  %v\n", r.PingLatency.AvgRTT.Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("  Max RTT:  %v\n", r.PingLatency.MaxRTT.Round(time.Microsecond)))
		sb.WriteString(fmt.Sprintf("  Std Dev:  %v\n", r.PingLatency.StdDev.Round(time.Microsecond)))
	}

	// Topics
	if len(r.Topics) > 0 {
		sb.WriteString("\nTopic Probing:\n")
		for _, t := range r.Topics {
			if t.Error != nil {
				sb.WriteString(fmt.Sprintf("  ⚠ %-30s  error: %v\n", t.Filter, t.Error))
			} else if t.Subscribed {
				sb.WriteString(fmt.Sprintf("  ✓ %-30s  QoS %d\n", t.Filter, t.QoS))
			} else {
				sb.WriteString(fmt.Sprintf("  ✗ %-30s  rejected\n", t.Filter))
			}
		}
	}

	// Security summary
	sb.WriteString("\nSecurity Assessment:\n")
	issues := 0
	if r.AuthResult.AnonAllowed {
		sb.WriteString("  ⚠ Anonymous connections accepted (no authentication)\n")
		issues++
	}
	if !r.UseTLS {
		sb.WriteString("  ⚠ No TLS encryption (plaintext MQTT)\n")
		issues++
	}
	for _, t := range r.Topics {
		if t.Subscribed && t.Filter == "#" {
			sb.WriteString("  ⚠ Wildcard topic '#' is subscribable (full access)\n")
			issues++
			break
		}
	}
	for _, t := range r.Topics {
		if t.Subscribed && strings.HasPrefix(t.Filter, "$SYS") {
			sb.WriteString("  ⚠ $SYS topics are accessible (system info leakage)\n")
			issues++
			break
		}
	}
	if issues == 0 {
		sb.WriteString("  ✓ No obvious security issues detected\n")
	}

	sb.WriteString(fmt.Sprintf("\nCompleted in %v\n", r.Duration.Round(time.Millisecond)))

	return sb.String()
}

// FormatCompact returns a single-line summary.
func (r *Result) FormatCompact() string {
	if !r.Connected {
		return fmt.Sprintf("✗ %s:%d  connection failed", r.Host, r.Port)
	}
	auth := "anon"
	if r.AuthResult.AuthRequired {
		auth = "auth-required"
	}
	tlsStr := "plain"
	if r.UseTLS {
		tlsStr = "tls"
	}
	return fmt.Sprintf("✓ %s:%d  %s  %s  ping=%v",
		r.Host, r.Port, auth, tlsStr, r.PingLatency.AvgRTT.Round(time.Microsecond))
}

// CheckMultiple checks multiple brokers concurrently.
func CheckMultiple(ctx context.Context, hosts []string, opts Options) map[string]*Result {
	results := make(map[string]*Result)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			o := opts
			o.Host = h
			checker := NewChecker(o)
			result, _ := checker.Check(ctx)
			mu.Lock()
			results[h] = result
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return results
}
