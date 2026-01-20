// Package cidr provides CIDR/subnet calculation utilities.
package cidr

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

// Subnet represents a network subnet with calculated information.
type Subnet struct {
	CIDR           string
	NetworkAddress string
	BroadcastAddr  string
	FirstHost      string
	LastHost       string
	SubnetMask     string
	WildcardMask   string
	TotalHosts     int
	UsableHosts    int
	Prefix         int
	IsIPv6         bool
}

// Parse parses a CIDR notation and returns subnet information.
func Parse(cidr string) (*Subnet, error) {
	// Handle bare IP without prefix
	if !strings.Contains(cidr, "/") {
		// Assume /32 for IPv4, /128 for IPv6
		if strings.Contains(cidr, ":") {
			cidr = cidr + "/128"
		} else {
			cidr = cidr + "/32"
		}
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ones, bits := ipNet.Mask.Size()

	subnet := &Subnet{
		CIDR:           ipNet.String(),
		NetworkAddress: ipNet.IP.String(),
		Prefix:         ones,
		IsIPv6:         bits == 128,
	}

	if bits == 32 {
		// IPv4
		subnet.SubnetMask = net.IP(ipNet.Mask).String()
		subnet.WildcardMask = wildcardMask(ipNet.Mask)
		subnet.BroadcastAddr = broadcastAddress(ipNet)
		subnet.FirstHost = firstHost(ipNet)
		subnet.LastHost = lastHost(ipNet)
		subnet.TotalHosts = int(math.Pow(2, float64(bits-ones)))
		if ones < 31 {
			subnet.UsableHosts = subnet.TotalHosts - 2
		} else if ones == 31 {
			subnet.UsableHosts = 2
		} else {
			subnet.UsableHosts = 1
		}
	} else {
		// IPv6
		subnet.SubnetMask = fmt.Sprintf("/%d", ones)
		subnet.TotalHosts = -1 // Too large to represent
		subnet.UsableHosts = -1
		// Calculate bounds for IPv6
		subnet.FirstHost = ip.String()
		subnet.LastHost = lastHostIPv6(ipNet)
	}

	return subnet, nil
}

// Contains checks if an IP is within a CIDR range.
func Contains(cidr, ip string) (bool, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR: %w", err)
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP: %s", ip)
	}

	return ipNet.Contains(parsedIP), nil
}

// Split splits a CIDR into smaller subnets.
func Split(cidr string, newPrefix int) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ones, bits := ipNet.Mask.Size()

	if newPrefix <= ones {
		return nil, fmt.Errorf("new prefix /%d must be larger than current /%d", newPrefix, ones)
	}

	if newPrefix > bits {
		return nil, fmt.Errorf("prefix /%d exceeds maximum /%d", newPrefix, bits)
	}

	// Calculate number of subnets
	numSubnets := int(math.Pow(2, float64(newPrefix-ones)))

	subnets := make([]string, 0, numSubnets)
	ip := ipNet.IP

	for i := 0; i < numSubnets; i++ {
		newMask := net.CIDRMask(newPrefix, bits)
		subnet := &net.IPNet{
			IP:   ip,
			Mask: newMask,
		}
		subnets = append(subnets, subnet.String())

		// Increment IP to next subnet
		ip = nextSubnet(ip, newPrefix, bits)
	}

	return subnets, nil
}

// Supernet combines two CIDRs into a larger supernet if possible.
func Supernet(cidr1, cidr2 string) (string, error) {
	_, net1, err := net.ParseCIDR(cidr1)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %s", cidr1)
	}

	_, net2, err := net.ParseCIDR(cidr2)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %s", cidr2)
	}

	ones1, bits1 := net1.Mask.Size()
	ones2, bits2 := net2.Mask.Size()

	if ones1 != ones2 || bits1 != bits2 {
		return "", fmt.Errorf("CIDRs must have the same prefix length")
	}

	// Try one prefix shorter
	newPrefix := ones1 - 1
	if newPrefix < 0 {
		return "", fmt.Errorf("cannot create supernet")
	}

	newMask := net.CIDRMask(newPrefix, bits1)
	super := &net.IPNet{
		IP:   net1.IP.Mask(newMask),
		Mask: newMask,
	}

	// Verify both networks are contained
	if !super.Contains(net1.IP) || !super.Contains(net2.IP) {
		return "", fmt.Errorf("networks are not adjacent")
	}

	return super.String(), nil
}

// IPRange returns all IPs in a CIDR range.
func IPRange(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipNet.Mask.Size()
	total := int(math.Pow(2, float64(bits-ones)))

	// Limit to prevent memory issues
	if total > 65536 {
		return nil, fmt.Errorf("range too large (%d IPs), maximum is 65536", total)
	}

	ips := make([]string, 0, total)
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	for ipNet.Contains(ip) {
		ips = append(ips, ip.String())
		incIP(ip)
	}

	return ips, nil
}

// IPToInt converts an IPv4 address to an integer.
func IPToInt(ip string) (uint32, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, fmt.Errorf("invalid IP: %s", ip)
	}

	ip4 := parsed.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ip)
	}

	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), nil
}

// IntToIP converts an integer to an IPv4 address.
func IntToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(n>>24)&0xFF,
		(n>>16)&0xFF,
		(n>>8)&0xFF,
		n&0xFF)
}

// MaskToPrefix converts a subnet mask to CIDR prefix.
func MaskToPrefix(mask string) (int, error) {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid mask format: %s", mask)
	}

	var maskBytes [4]byte
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return 0, fmt.Errorf("invalid mask octet: %s", p)
		}
		maskBytes[i] = byte(n)
	}

	ipMask := net.IPMask(maskBytes[:])
	ones, _ := ipMask.Size()

	return ones, nil
}

// PrefixToMask converts a CIDR prefix to subnet mask.
func PrefixToMask(prefix int) (string, error) {
	if prefix < 0 || prefix > 32 {
		return "", fmt.Errorf("invalid prefix: %d", prefix)
	}

	mask := net.CIDRMask(prefix, 32)
	return net.IP(mask).String(), nil
}

// Helper functions

func wildcardMask(mask net.IPMask) string {
	wildcard := make(net.IP, len(mask))
	for i, b := range mask {
		wildcard[i] = ^b
	}
	return wildcard.String()
}

func broadcastAddress(ipNet *net.IPNet) string {
	ip := ipNet.IP.To4()
	if ip == nil {
		return ""
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip[i] | ^ipNet.Mask[i]
	}
	return broadcast.String()
}

func firstHost(ipNet *net.IPNet) string {
	ones, _ := ipNet.Mask.Size()
	if ones >= 31 {
		return ipNet.IP.String()
	}

	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	ip[len(ip)-1]++
	return ip.String()
}

func lastHost(ipNet *net.IPNet) string {
	ones, _ := ipNet.Mask.Size()
	if ones >= 31 {
		return broadcastAddress(ipNet)
	}

	broadcast := net.ParseIP(broadcastAddress(ipNet)).To4()
	broadcast[3]--
	return broadcast.String()
}

func lastHostIPv6(ipNet *net.IPNet) string {
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	for i := range ip {
		ip[i] |= ^ipNet.Mask[i]
	}
	return ip.String()
}

func nextSubnet(ip net.IP, prefix, bits int) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	// Calculate the size of one subnet in addresses: 2^(bits - prefix)
	// For IPv4 /26: 2^(32-26) = 64 addresses per subnet
	hostBits := uint(bits - prefix)

	// Find which byte(s) to increment
	// The least significant bit of the network portion is at bit position (prefix-1)
	// from the left, or equivalently, at bit position (bits - prefix) from the right.
	// We need to add 2^hostBits to the IP address.

	// Convert to 4-byte representation for IPv4
	ip4 := next.To4()
	if ip4 != nil {
		next = ip4
	}

	// Calculate which byte and bit to start from
	// hostBits tells us how many bits are in the host portion
	// The network boundary is at byte (bits - hostBits) / 8 from the perspective of incrementing
	incrementByteFromEnd := int(hostBits / 8)
	incrementBit := hostBits % 8

	startByte := len(next) - 1 - incrementByteFromEnd

	if startByte < 0 || startByte >= len(next) {
		return next
	}

	// Increment value for this byte
	increment := uint16(1 << incrementBit)

	for i := startByte; i >= 0; i-- {
		sum := uint16(next[i]) + increment
		next[i] = byte(sum & 0xFF)
		increment = sum >> 8 // carry
		if increment == 0 {
			break
		}
	}

	return next
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
