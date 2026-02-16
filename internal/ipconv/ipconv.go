// Package ipconv converts IP addresses between decimal, hex, octal, binary,
// and integer representations.
package ipconv

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

// Format represents an IP address representation format.
type Format string

const (
	FormatDecimal Format = "decimal"
	FormatHex     Format = "hex"
	FormatOctal   Format = "octal"
	FormatBinary  Format = "binary"
	FormatInteger Format = "integer"
	FormatMapped  Format = "mapped"
)

// AllFormats returns all supported output formats.
func AllFormats() []Format {
	return []Format{FormatDecimal, FormatHex, FormatOctal, FormatBinary, FormatInteger, FormatMapped}
}

// Conversion holds all representations of an IP address.
type Conversion struct {
	Input      string `json:"input"`
	Decimal    string `json:"decimal"`
	Hex        string `json:"hex"`
	HexCompact string `json:"hex_compact"`
	Octal      string `json:"octal"`
	Binary     string `json:"binary"`
	Integer    string `json:"integer"`
	Mapped     string `json:"mapped,omitempty"`
	IsIPv6     bool   `json:"is_ipv6"`
	Reverse    string `json:"reverse_dns"`
	Valid      bool   `json:"valid"`
	Error      string `json:"error,omitempty"`
}

// Convert takes an IP string in any format and returns all representations.
func Convert(input string) Conversion {
	c := Conversion{Input: input}

	ip := parseFlexible(input)
	if ip == nil {
		c.Valid = false
		c.Error = fmt.Sprintf("cannot parse '%s' as IP address", input)
		return c
	}

	c.Valid = true
	c.IsIPv6 = ip.To4() == nil

	if c.IsIPv6 {
		c.Decimal = ip.String()
		c.Hex = toHexIPv6(ip)
		c.HexCompact = "0x" + fmt.Sprintf("%x", ipToInt(ip))
		c.Octal = toOctalIPv6(ip)
		c.Binary = toBinaryIPv6(ip)
		c.Integer = ipToInt(ip).String()
		c.Reverse = toReverseIPv6(ip)
	} else {
		ip4 := ip.To4()
		c.Decimal = ip4.String()
		c.Hex = toHexIPv4(ip4)
		c.HexCompact = fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(ip4))
		c.Octal = toOctalIPv4(ip4)
		c.Binary = toBinaryIPv4(ip4)
		c.Integer = fmt.Sprintf("%d", binary.BigEndian.Uint32(ip4))
		c.Mapped = fmt.Sprintf("::ffff:%s", ip4.String())
		c.Reverse = toReverseIPv4(ip4)
	}

	return c
}

// FromInteger converts a decimal integer string to an IP address.
func FromInteger(s string) Conversion {
	c := Conversion{Input: s}

	n := new(big.Int)
	n, ok := n.SetString(s, 10)
	if !ok {
		c.Valid = false
		c.Error = fmt.Sprintf("cannot parse '%s' as integer", s)
		return c
	}

	if n.Sign() < 0 {
		c.Valid = false
		c.Error = "negative integers are not valid IP addresses"
		return c
	}

	maxIPv4 := new(big.Int).SetUint64(0xFFFFFFFF)
	if n.Cmp(maxIPv4) <= 0 {
		b := make([]byte, 4)
		nBytes := n.Bytes()
		copy(b[4-len(nBytes):], nBytes)
		ip := net.IP(b)
		return Convert(ip.String())
	}

	maxIPv6 := new(big.Int)
	maxIPv6.SetString("340282366920938463463374607431768211455", 10)
	if n.Cmp(maxIPv6) > 0 {
		c.Valid = false
		c.Error = "integer too large for IPv6"
		return c
	}

	b := make([]byte, 16)
	nBytes := n.Bytes()
	copy(b[16-len(nBytes):], nBytes)
	ip := net.IP(b)
	return Convert(ip.String())
}

// parseFlexible tries to parse an IP from various formats.
func parseFlexible(input string) net.IP {
	input = strings.TrimSpace(input)

	// Standard dotted decimal or IPv6
	if ip := net.ParseIP(input); ip != nil {
		return ip
	}

	// Hex format: 0xC0A80001 or 0xc0.0xa8.0x00.0x01
	if strings.HasPrefix(input, "0x") || strings.HasPrefix(input, "0X") {
		if strings.Contains(input, ".") {
			return parseHexDotted(input)
		}
		return parseHexCompact(input)
	}

	// Octal format: 0300.0250.0000.0001
	if strings.Contains(input, ".") && strings.HasPrefix(input, "0") {
		if ip := parseOctalDotted(input); ip != nil {
			return ip
		}
	}

	// Pure integer
	if n, err := strconv.ParseUint(input, 10, 64); err == nil {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(n))
		return net.IP(b)
	}

	return nil
}

func parseHexDotted(input string) net.IP {
	parts := strings.Split(input, ".")
	if len(parts) != 4 {
		return nil
	}
	b := make([]byte, 4)
	for i, p := range parts {
		p = strings.TrimPrefix(strings.TrimPrefix(p, "0x"), "0X")
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil
		}
		b[i] = byte(v)
	}
	return net.IP(b)
}

func parseHexCompact(input string) net.IP {
	hex := strings.TrimPrefix(strings.TrimPrefix(input, "0x"), "0X")
	if len(hex) <= 8 {
		for len(hex) < 8 {
			hex = "0" + hex
		}
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
			if err != nil {
				return nil
			}
			b[i] = byte(v)
		}
		return net.IP(b)
	}
	return nil
}

func parseOctalDotted(input string) net.IP {
	parts := strings.Split(input, ".")
	if len(parts) != 4 {
		return nil
	}
	b := make([]byte, 4)
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 8, 8)
		if err != nil {
			return nil
		}
		b[i] = byte(v)
	}
	return net.IP(b)
}

func toHexIPv4(ip net.IP) string {
	return fmt.Sprintf("0x%02x.0x%02x.0x%02x.0x%02x", ip[0], ip[1], ip[2], ip[3])
}

func toOctalIPv4(ip net.IP) string {
	return fmt.Sprintf("0%03o.0%03o.0%03o.0%03o", ip[0], ip[1], ip[2], ip[3])
}

func toBinaryIPv4(ip net.IP) string {
	parts := make([]string, 4)
	for i, b := range ip {
		parts[i] = fmt.Sprintf("%08b", b)
	}
	return strings.Join(parts, ".")
}

func toHexIPv6(ip net.IP) string {
	ip16 := ip.To16()
	parts := make([]string, 8)
	for i := 0; i < 16; i += 2 {
		parts[i/2] = fmt.Sprintf("%02x%02x", ip16[i], ip16[i+1])
	}
	return strings.Join(parts, ":")
}

func toOctalIPv6(ip net.IP) string {
	ip16 := ip.To16()
	parts := make([]string, 16)
	for i, b := range ip16 {
		parts[i] = fmt.Sprintf("0%03o", b)
	}
	return strings.Join(parts, ".")
}

func toBinaryIPv6(ip net.IP) string {
	ip16 := ip.To16()
	parts := make([]string, 16)
	for i, b := range ip16 {
		parts[i] = fmt.Sprintf("%08b", b)
	}
	return strings.Join(parts, "")
}

func toReverseIPv4(ip net.IP) string {
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip[3], ip[2], ip[1], ip[0])
}

func toReverseIPv6(ip net.IP) string {
	ip16 := ip.To16()
	nibbles := make([]string, 32)
	for i := 0; i < 16; i++ {
		nibbles[31-i*2] = fmt.Sprintf("%x", ip16[i]>>4)
		nibbles[31-i*2-1] = fmt.Sprintf("%x", ip16[i]&0x0f)
	}
	return strings.Join(nibbles, ".") + ".ip6.arpa"
}

func ipToInt(ip net.IP) *big.Int {
	ip16 := ip.To16()
	return new(big.Int).SetBytes(ip16)
}

// FormatConversion returns a human-readable view of all representations.
func FormatConversion(c Conversion) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Input:       %s\n", c.Input))

	if !c.Valid {
		sb.WriteString(fmt.Sprintf("  Error:       %s\n", c.Error))
		return sb.String()
	}

	if c.IsIPv6 {
		sb.WriteString("  Type:        IPv6\n")
	} else {
		sb.WriteString("  Type:        IPv4\n")
	}

	sb.WriteString(fmt.Sprintf("  Decimal:     %s\n", c.Decimal))
	sb.WriteString(fmt.Sprintf("  Hex:         %s\n", c.Hex))
	sb.WriteString(fmt.Sprintf("  Hex (int):   %s\n", c.HexCompact))
	sb.WriteString(fmt.Sprintf("  Octal:       %s\n", c.Octal))
	sb.WriteString(fmt.Sprintf("  Binary:      %s\n", c.Binary))
	sb.WriteString(fmt.Sprintf("  Integer:     %s\n", c.Integer))

	if c.Mapped != "" {
		sb.WriteString(fmt.Sprintf("  IPv6 Mapped: %s\n", c.Mapped))
	}

	sb.WriteString(fmt.Sprintf("  Reverse DNS: %s\n", c.Reverse))

	return sb.String()
}
