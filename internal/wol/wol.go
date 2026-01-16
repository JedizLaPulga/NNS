// Package wol provides Wake-on-LAN functionality.
package wol

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// MagicPacket represents a Wake-on-LAN magic packet.
type MagicPacket struct {
	header  [6]byte
	payload [96]byte // 16 repetitions of 6-byte MAC
}

// New creates a new magic packet for the given MAC address.
func New(mac string) (*MagicPacket, error) {
	macBytes, err := ParseMAC(mac)
	if err != nil {
		return nil, err
	}

	packet := &MagicPacket{}

	// Set header (6 bytes of 0xFF)
	for i := 0; i < 6; i++ {
		packet.header[i] = 0xFF
	}

	// Set payload (MAC address repeated 16 times)
	for i := 0; i < 16; i++ {
		copy(packet.payload[i*6:(i+1)*6], macBytes)
	}

	return packet, nil
}

// Bytes returns the raw bytes of the magic packet.
func (mp *MagicPacket) Bytes() []byte {
	data := make([]byte, 102)
	copy(data[0:6], mp.header[:])
	copy(data[6:102], mp.payload[:])
	return data
}

// ParseMAC parses a MAC address string into bytes.
func ParseMAC(mac string) ([]byte, error) {
	// Normalize MAC address
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ReplaceAll(mac, ".", ":")

	// Remove colons for parsing
	cleanMAC := strings.ReplaceAll(mac, ":", "")

	// Validate length
	if len(cleanMAC) != 12 {
		return nil, fmt.Errorf("invalid MAC address length: %s", mac)
	}

	// Validate hex characters
	validMAC := regexp.MustCompile(`^[0-9a-f]{12}$`)
	if !validMAC.MatchString(cleanMAC) {
		return nil, fmt.Errorf("invalid MAC address format: %s", mac)
	}

	// Decode hex
	bytes, err := hex.DecodeString(cleanMAC)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MAC: %w", err)
	}

	return bytes, nil
}

// Wake sends a Wake-on-LAN magic packet to the specified MAC address.
func Wake(mac string, broadcast string, port int) error {
	packet, err := New(mac)
	if err != nil {
		return err
	}

	// Default broadcast address
	if broadcast == "" {
		broadcast = "255.255.255.255"
	}

	// Default port
	if port == 0 {
		port = 9
	}

	// Create UDP connection
	addr := fmt.Sprintf("%s:%d", broadcast, port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Send magic packet
	_, err = conn.Write(packet.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

// WakeWithInterface sends a WoL packet using a specific network interface.
func WakeWithInterface(mac string, iface string, port int) error {
	packet, err := New(mac)
	if err != nil {
		return err
	}

	if port == 0 {
		port = 9
	}

	// Get interface
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	// Get broadcast address for this interface
	addrs, err := netIface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get interface addresses: %w", err)
	}

	var broadcastAddr string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			// Calculate broadcast address
			ip := ipnet.IP.To4()
			mask := ipnet.Mask
			broadcast := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				broadcast[i] = ip[i] | ^mask[i]
			}
			broadcastAddr = broadcast.String()
			break
		}
	}

	if broadcastAddr == "" {
		broadcastAddr = "255.255.255.255"
	}

	// Send packet
	addr := fmt.Sprintf("%s:%d", broadcastAddr, port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

// FormatMAC formats a MAC address with colons.
func FormatMAC(mac string) string {
	clean := strings.ToLower(mac)
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, ".", "")

	if len(clean) != 12 {
		return mac
	}

	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = clean[i*2 : i*2+2]
	}

	return strings.Join(parts, ":")
}
