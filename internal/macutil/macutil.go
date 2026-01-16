// Package macutil provides MAC address utilities.
package macutil

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"

	"github.com/JedizLaPulga/NNS/internal/arp"
)

// Info holds MAC address information.
type Info struct {
	MAC         string
	Normalized  string
	Vendor      string
	IsMulticast bool
	IsLocal     bool
	OUI         string
}

// Parse parses and validates a MAC address.
func Parse(mac string) (*Info, error) {
	normalized := Normalize(mac)
	if normalized == "" {
		return nil, fmt.Errorf("invalid MAC address: %s", mac)
	}

	info := &Info{
		MAC:        mac,
		Normalized: normalized,
		Vendor:     arp.LookupVendor(normalized),
	}

	// Extract OUI (first 3 bytes)
	parts := strings.Split(normalized, ":")
	if len(parts) >= 3 {
		info.OUI = strings.Join(parts[:3], ":")
	}

	// Check multicast bit (first byte, bit 0)
	firstByte := parts[0]
	if len(firstByte) == 2 {
		var b byte
		fmt.Sscanf(firstByte, "%x", &b)
		info.IsMulticast = (b & 0x01) != 0
		info.IsLocal = (b & 0x02) != 0
	}

	return info, nil
}

// Normalize normalizes a MAC address to colon-separated lowercase format.
func Normalize(mac string) string {
	// Remove common separators
	clean := strings.ToLower(mac)
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, ".", "")
	clean = strings.ReplaceAll(clean, " ", "")

	// Validate length
	if len(clean) != 12 {
		return ""
	}

	// Validate hex characters
	validMAC := regexp.MustCompile(`^[0-9a-f]{12}$`)
	if !validMAC.MatchString(clean) {
		return ""
	}

	// Format with colons
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = clean[i*2 : i*2+2]
	}

	return strings.Join(parts, ":")
}

// Format formats a MAC address in the specified style.
func Format(mac string, style string) string {
	normalized := Normalize(mac)
	if normalized == "" {
		return mac
	}

	parts := strings.Split(normalized, ":")

	switch strings.ToLower(style) {
	case "colon", ":":
		return strings.Join(parts, ":")
	case "dash", "-":
		return strings.Join(parts, "-")
	case "dot", ".":
		// Cisco style: xxxx.xxxx.xxxx
		return fmt.Sprintf("%s%s.%s%s.%s%s",
			parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
	case "bare", "none":
		return strings.Join(parts, "")
	case "upper":
		return strings.ToUpper(strings.Join(parts, ":"))
	default:
		return normalized
	}
}

// Generate generates a random MAC address.
func Generate(local bool) string {
	mac := make([]byte, 6)
	rand.Read(mac)

	// Set locally administered bit
	if local {
		mac[0] |= 0x02
	} else {
		mac[0] &^= 0x02
	}

	// Clear multicast bit (unicast)
	mac[0] &^= 0x01

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// GenerateWithOUI generates a random MAC with a specified OUI.
func GenerateWithOUI(oui string) (string, error) {
	// Parse OUI
	ouiClean := strings.ToLower(oui)
	ouiClean = strings.ReplaceAll(ouiClean, "-", "")
	ouiClean = strings.ReplaceAll(ouiClean, ":", "")

	if len(ouiClean) != 6 {
		return "", fmt.Errorf("invalid OUI: %s", oui)
	}

	validOUI := regexp.MustCompile(`^[0-9a-f]{6}$`)
	if !validOUI.MatchString(ouiClean) {
		return "", fmt.Errorf("invalid OUI format: %s", oui)
	}

	// Generate random NIC part
	nic := make([]byte, 3)
	rand.Read(nic)

	return fmt.Sprintf("%s:%s:%s:%02x:%02x:%02x",
		ouiClean[0:2], ouiClean[2:4], ouiClean[4:6],
		nic[0], nic[1], nic[2]), nil
}

// IsValid checks if a MAC address is valid.
func IsValid(mac string) bool {
	return Normalize(mac) != ""
}

// IsBroadcast checks if a MAC is the broadcast address.
func IsBroadcast(mac string) bool {
	return Normalize(mac) == "ff:ff:ff:ff:ff:ff"
}

// IsZero checks if a MAC is all zeros.
func IsZero(mac string) bool {
	return Normalize(mac) == "00:00:00:00:00:00"
}

// Compare compares two MAC addresses.
func Compare(mac1, mac2 string) bool {
	return Normalize(mac1) == Normalize(mac2)
}

// CommonVendorOUIs provides common vendor OUIs for testing.
var CommonVendorOUIs = map[string]string{
	"00:00:0c": "Cisco",
	"00:50:56": "VMware",
	"08:00:27": "VirtualBox",
	"00:0c:29": "VMware",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"00:1a:11": "Google",
	"3c:5a:b4": "Google",
}
