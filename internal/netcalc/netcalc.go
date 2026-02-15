// Package netcalc provides IP address arithmetic and network calculations.
package netcalc

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

// IPInfo holds computed information about an IP address within a network.
type IPInfo struct {
	IP          net.IP     `json:"ip"`
	Network     *net.IPNet `json:"network"`
	NetworkAddr net.IP     `json:"network_address"`
	Broadcast   net.IP     `json:"broadcast"`
	Netmask     net.IP     `json:"netmask"`
	Wildcard    net.IP     `json:"wildcard"`
	PrefixLen   int        `json:"prefix_len"`
	HostBits    int        `json:"host_bits"`
	TotalHosts  *big.Int   `json:"total_hosts"`
	UsableHosts *big.Int   `json:"usable_hosts"`
	FirstUsable net.IP     `json:"first_usable"`
	LastUsable  net.IP     `json:"last_usable"`
	IsIPv6      bool       `json:"is_ipv6"`
	Binary      string     `json:"binary"`
	IPClass     string     `json:"ip_class"`
	IsPrivate   bool       `json:"is_private"`
}

// Calculate computes full network information for a CIDR string.
func Calculate(cidr string) (*IPInfo, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try bare IP
		ip = net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("invalid CIDR or IP: %s", cidr)
		}
		if ip.To4() != nil {
			_, network, _ = net.ParseCIDR(ip.String() + "/32")
		} else {
			_, network, _ = net.ParseCIDR(ip.String() + "/128")
		}
	}

	isV6 := ip.To4() == nil
	info := &IPInfo{
		IP:      ip,
		Network: network,
		IsIPv6:  isV6,
	}

	ones, bits := network.Mask.Size()
	info.PrefixLen = ones
	info.HostBits = bits - ones

	// Network address
	info.NetworkAddr = network.IP

	// Netmask
	info.Netmask = net.IP(network.Mask)

	// Wildcard mask
	info.Wildcard = wildcardMask(network.Mask)

	// Broadcast
	info.Broadcast = broadcastAddr(network)

	// Host counts
	info.TotalHosts = new(big.Int).Lsh(big.NewInt(1), uint(info.HostBits))
	if !isV6 && info.HostBits >= 2 {
		info.UsableHosts = new(big.Int).Sub(info.TotalHosts, big.NewInt(2))
	} else if info.HostBits <= 1 {
		info.UsableHosts = info.TotalHosts
	} else {
		info.UsableHosts = new(big.Int).Sub(info.TotalHosts, big.NewInt(2))
	}

	// First/last usable
	info.FirstUsable = nextIP(info.NetworkAddr)
	info.LastUsable = prevIP(info.Broadcast)

	// Binary representation
	info.Binary = ipToBinary(ip)

	// Class (IPv4 only)
	if !isV6 {
		info.IPClass = ipClass(ip)
		info.IsPrivate = isPrivateIP(ip)
	}

	return info, nil
}

// AddToIP adds an offset to an IP address.
func AddToIP(ipStr string, offset int64) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}

	ipInt := ipToInt(ip)
	ipInt.Add(ipInt, big.NewInt(offset))
	return intToIP(ipInt, ip.To4() != nil), nil
}

// IPRange returns all IPs between start and end (inclusive), capped at maxCount.
func IPRange(startStr, endStr string, maxCount int) ([]net.IP, error) {
	start := net.ParseIP(startStr)
	end := net.ParseIP(endStr)
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP range: %s - %s", startStr, endStr)
	}

	startInt := ipToInt(start)
	endInt := ipToInt(end)

	if startInt.Cmp(endInt) > 0 {
		return nil, fmt.Errorf("start IP is greater than end IP")
	}

	diff := new(big.Int).Sub(endInt, startInt)
	count := int(diff.Int64()) + 1
	if count > maxCount {
		count = maxCount
	}

	isV4 := start.To4() != nil
	ips := make([]net.IP, 0, count)
	current := new(big.Int).Set(startInt)
	for i := 0; i < count; i++ {
		ips = append(ips, intToIP(current, isV4))
		current.Add(current, big.NewInt(1))
	}
	return ips, nil
}

// IPToBinary returns the binary string representation of an IP.
func IPToBinary(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", ipStr)
	}
	return ipToBinary(ip), nil
}

// FormatInfo returns a human-readable representation of IPInfo.
func FormatInfo(info *IPInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  IP Address:      %s\n", info.IP))
	sb.WriteString(fmt.Sprintf("  Network:         %s\n", info.Network))
	sb.WriteString(fmt.Sprintf("  Network Addr:    %s\n", info.NetworkAddr))
	sb.WriteString(fmt.Sprintf("  Broadcast:       %s\n", info.Broadcast))
	sb.WriteString(fmt.Sprintf("  Netmask:         %s\n", info.Netmask))
	sb.WriteString(fmt.Sprintf("  Wildcard:        %s\n", info.Wildcard))
	sb.WriteString(fmt.Sprintf("  Prefix Length:   /%d\n", info.PrefixLen))
	sb.WriteString(fmt.Sprintf("  Host Bits:       %d\n", info.HostBits))
	sb.WriteString(fmt.Sprintf("  Total Hosts:     %s\n", info.TotalHosts.String()))
	sb.WriteString(fmt.Sprintf("  Usable Hosts:    %s\n", info.UsableHosts.String()))
	sb.WriteString(fmt.Sprintf("  First Usable:    %s\n", info.FirstUsable))
	sb.WriteString(fmt.Sprintf("  Last Usable:     %s\n", info.LastUsable))
	sb.WriteString(fmt.Sprintf("  Binary:          %s\n", info.Binary))

	if !info.IsIPv6 {
		sb.WriteString(fmt.Sprintf("  Class:           %s\n", info.IPClass))
		sb.WriteString(fmt.Sprintf("  Private:         %v\n", info.IsPrivate))
	} else {
		sb.WriteString("  Type:            IPv6\n")
	}

	return sb.String()
}

// --- helpers ---

func wildcardMask(mask net.IPMask) net.IP {
	wild := make(net.IP, len(mask))
	for i, b := range mask {
		wild[i] = ^b
	}
	return wild
}

func broadcastAddr(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	for i := range n.IP {
		ip[i] = n.IP[i] | ^n.Mask[i]
	}
	return ip
}

func ipToInt(ip net.IP) *big.Int {
	if v4 := ip.To4(); v4 != nil {
		return new(big.Int).SetBytes(v4)
	}
	return new(big.Int).SetBytes(ip.To16())
}

func intToIP(n *big.Int, isV4 bool) net.IP {
	b := n.Bytes()
	if isV4 {
		ip := make(net.IP, 4)
		offset := 4 - len(b)
		if offset < 0 {
			offset = 0
		}
		copy(ip[offset:], b)
		return ip
	}
	ip := make(net.IP, 16)
	offset := 16 - len(b)
	if offset < 0 {
		offset = 0
	}
	copy(ip[offset:], b)
	return ip
}

func nextIP(ip net.IP) net.IP {
	n := ipToInt(ip)
	n.Add(n, big.NewInt(1))
	return intToIP(n, ip.To4() != nil)
}

func prevIP(ip net.IP) net.IP {
	n := ipToInt(ip)
	n.Sub(n, big.NewInt(1))
	return intToIP(n, ip.To4() != nil)
}

func ipToBinary(ip net.IP) string {
	var raw []byte
	if v4 := ip.To4(); v4 != nil {
		raw = v4
	} else {
		raw = ip.To16()
	}
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%08b", b)
	}
	return strings.Join(parts, ".")
}

func ipClass(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return "N/A"
	}
	first := v4[0]
	switch {
	case first < 128:
		return "A"
	case first < 192:
		return "B"
	case first < 224:
		return "C"
	case first < 240:
		return "D (Multicast)"
	default:
		return "E (Reserved)"
	}
}

func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
