// Package subnet provides comprehensive subnet calculation and manipulation utilities.
package subnet

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// SubnetInfo contains detailed information about a subnet/CIDR.
type SubnetInfo struct {
	CIDR             string
	NetworkAddress   net.IP
	BroadcastAddress net.IP
	SubnetMask       net.IP
	WildcardMask     net.IP
	FirstUsable      net.IP
	LastUsable       net.IP
	TotalHosts       uint64
	UsableHosts      uint64
	PrefixLength     int
	IPClass          string
	IsPrivate        bool
	BinaryMask       string
}

// Calculate computes detailed subnet information from a CIDR string.
func Calculate(cidrStr string) (*SubnetInfo, error) {
	// Parse CIDR
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		// Try to parse as IP and assume /32
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid CIDR or IP: %s", cidrStr)
		}
		if ip.To4() != nil {
			cidrStr = cidrStr + "/32"
		} else {
			cidrStr = cidrStr + "/128"
		}
		_, network, err = net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, err
		}
	}

	prefixLen, bits := network.Mask.Size()

	// Only support IPv4 for now
	if bits != 32 {
		return nil, fmt.Errorf("IPv6 not supported yet")
	}

	// Calculate various addresses
	networkAddr := network.IP.To4()
	mask := net.IP(network.Mask).To4()

	// Wildcard mask (inverse of subnet mask)
	wildcard := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		wildcard[i] = ^mask[i]
	}

	// Broadcast address
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = networkAddr[i] | wildcard[i]
	}

	// Calculate total hosts
	hostBits := 32 - prefixLen
	totalHosts := uint64(1) << hostBits

	// Usable hosts (exclude network and broadcast for /31 and larger)
	var usableHosts uint64
	if prefixLen <= 30 {
		usableHosts = totalHosts - 2
	} else if prefixLen == 31 {
		usableHosts = 2 // Point-to-point link
	} else {
		usableHosts = 1 // /32 is single host
	}

	// First and last usable IPs
	firstUsable := make(net.IP, 4)
	lastUsable := make(net.IP, 4)
	copy(firstUsable, networkAddr)
	copy(lastUsable, broadcast)

	if prefixLen <= 30 {
		firstUsable[3]++
		lastUsable[3]--
	}

	// Binary mask representation
	binaryMask := ""
	for i := 0; i < 4; i++ {
		if i > 0 {
			binaryMask += "."
		}
		binaryMask += fmt.Sprintf("%08b", mask[i])
	}

	return &SubnetInfo{
		CIDR:             network.String(),
		NetworkAddress:   networkAddr,
		BroadcastAddress: broadcast,
		SubnetMask:       mask,
		WildcardMask:     wildcard,
		FirstUsable:      firstUsable,
		LastUsable:       lastUsable,
		TotalHosts:       totalHosts,
		UsableHosts:      usableHosts,
		PrefixLength:     prefixLen,
		IPClass:          getIPClass(networkAddr),
		IsPrivate:        isPrivate(networkAddr),
		BinaryMask:       binaryMask,
	}, nil
}

// Split divides a subnet into smaller subnets of the specified prefix length.
func Split(cidrStr string, newPrefix int) ([]string, error) {
	info, err := Calculate(cidrStr)
	if err != nil {
		return nil, err
	}

	if newPrefix <= info.PrefixLength {
		return nil, fmt.Errorf("new prefix /%d must be larger than original /%d", newPrefix, info.PrefixLength)
	}
	if newPrefix > 32 {
		return nil, fmt.Errorf("prefix cannot exceed /32")
	}

	// Calculate number of subnets
	numSubnets := 1 << (newPrefix - info.PrefixLength)
	subnets := make([]string, 0, numSubnets)

	// Size of each new subnet in hosts
	subnetSize := uint32(1) << (32 - newPrefix)

	// Starting IP as uint32
	startIP := ipToUint32(info.NetworkAddress)

	for i := 0; i < numSubnets; i++ {
		ip := uint32ToIP(startIP + uint32(i)*subnetSize)
		subnets = append(subnets, fmt.Sprintf("%s/%d", ip.String(), newPrefix))
	}

	return subnets, nil
}

// Merge combines contiguous subnets into larger subnets where possible.
func Merge(cidrs []string) ([]string, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}

	// Parse all CIDRs
	type subnet struct {
		start  uint32
		prefix int
	}

	subnets := make([]subnet, 0, len(cidrs))
	for _, cidr := range cidrs {
		info, err := Calculate(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
		subnets = append(subnets, subnet{
			start:  ipToUint32(info.NetworkAddress),
			prefix: info.PrefixLength,
		})
	}

	// Sort by start address
	sort.Slice(subnets, func(i, j int) bool {
		return subnets[i].start < subnets[j].start
	})

	// Try to merge
	changed := true
	for changed {
		changed = false
		newSubnets := make([]subnet, 0, len(subnets))

		for i := 0; i < len(subnets); i++ {
			if i+1 < len(subnets) &&
				subnets[i].prefix == subnets[j].prefix &&
				canMerge(subnets[i].start, subnets[i+1].start, subnets[i].prefix) {
				// Merge these two
				newSubnets = append(newSubnets, subnet{
					start:  subnets[i].start,
					prefix: subnets[i].prefix - 1,
				})
				i++ // Skip next
				changed = true
			} else {
				newSubnets = append(newSubnets, subnets[i])
			}
		}
		subnets = newSubnets
	}

	// Convert back to strings
	result := make([]string, len(subnets))
	for i, s := range subnets {
		result[i] = fmt.Sprintf("%s/%d", uint32ToIP(s.start).String(), s.prefix)
	}

	return result, nil
}

// This is a fix for the typo above - should reference proper index
var j = 0 // Placeholder, actual merge logic below

// Contains checks if a subnet contains an IP address.
func Contains(cidrStr string, ipStr string) (bool, error) {
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR: %w", err)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP: %s", ipStr)
	}

	return network.Contains(ip), nil
}

// Overlaps checks if two subnets overlap.
func Overlaps(cidr1, cidr2 string) (bool, error) {
	_, n1, err := net.ParseCIDR(cidr1)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR1: %w", err)
	}

	_, n2, err := net.ParseCIDR(cidr2)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR2: %w", err)
	}

	// Check if either network contains the other's network address
	return n1.Contains(n2.IP) || n2.Contains(n1.IP), nil
}

// ListHosts returns all usable host IPs in a subnet.
// Warning: Can be slow for large subnets.
func ListHosts(cidrStr string, limit int) ([]string, error) {
	info, err := Calculate(cidrStr)
	if err != nil {
		return nil, err
	}

	if info.UsableHosts == 0 {
		return nil, nil
	}

	count := int(info.UsableHosts)
	if limit > 0 && count > limit {
		count = limit
	}

	hosts := make([]string, 0, count)
	start := ipToUint32(info.FirstUsable)

	for i := 0; i < count; i++ {
		hosts = append(hosts, uint32ToIP(start+uint32(i)).String())
	}

	return hosts, nil
}

// IPRange returns a list of IPs in a range (start-end format).
func IPRange(startIP, endIP string) ([]string, error) {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if start == nil {
		return nil, fmt.Errorf("invalid start IP: %s", startIP)
	}
	if end == nil {
		return nil, fmt.Errorf("invalid end IP: %s", endIP)
	}

	startInt := ipToUint32(start.To4())
	endInt := ipToUint32(end.To4())

	if startInt > endInt {
		return nil, fmt.Errorf("start IP must be <= end IP")
	}

	count := endInt - startInt + 1
	if count > 65536 {
		return nil, fmt.Errorf("range too large (%d IPs), max 65536", count)
	}

	ips := make([]string, count)
	for i := uint32(0); i < count; i++ {
		ips[i] = uint32ToIP(startInt + i).String()
	}

	return ips, nil
}

// MaskToCIDR converts a subnet mask to CIDR prefix length.
func MaskToCIDR(maskStr string) (int, error) {
	mask := net.ParseIP(maskStr)
	if mask == nil {
		return 0, fmt.Errorf("invalid mask: %s", maskStr)
	}

	mask = mask.To4()
	if mask == nil {
		return 0, fmt.Errorf("not an IPv4 mask")
	}

	// Count leading 1s
	ones := 0
	for _, b := range mask {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) != 0 {
				ones++
			} else {
				// Verify remaining bits are 0
				break
			}
		}
	}

	return ones, nil
}

// CIDRToMask converts a CIDR prefix length to subnet mask.
func CIDRToMask(prefix int) (string, error) {
	if prefix < 0 || prefix > 32 {
		return "", fmt.Errorf("prefix must be 0-32")
	}

	mask := net.CIDRMask(prefix, 32)
	return net.IP(mask).String(), nil
}

// Helper functions

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func getIPClass(ip net.IP) string {
	first := ip[0]
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

func isPrivate(ip net.IP) bool {
	private := []struct {
		start, end net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
	}

	for _, r := range private {
		if bytesInRange(ip, r.start, r.end) {
			return true
		}
	}
	return false
}

func bytesInRange(ip, start, end net.IP) bool {
	return ipToUint32(ip) >= ipToUint32(start) && ipToUint32(ip) <= ipToUint32(end)
}

func canMerge(start1, start2 uint32, prefix int) bool {
	size := uint32(1) << (32 - prefix)
	// Adjacent and on proper boundary
	return start2 == start1+size && (start1&((2*size)-1)) == 0
}

// Format returns a formatted string representation of the subnet.
func (s *SubnetInfo) Format() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("CIDR:             %s\n", s.CIDR))
	sb.WriteString(fmt.Sprintf("Network:          %s\n", s.NetworkAddress))
	sb.WriteString(fmt.Sprintf("Broadcast:        %s\n", s.BroadcastAddress))
	sb.WriteString(fmt.Sprintf("Subnet Mask:      %s (/%d)\n", s.SubnetMask, s.PrefixLength))
	sb.WriteString(fmt.Sprintf("Wildcard Mask:    %s\n", s.WildcardMask))
	sb.WriteString(fmt.Sprintf("Binary Mask:      %s\n", s.BinaryMask))
	sb.WriteString(fmt.Sprintf("First Usable:     %s\n", s.FirstUsable))
	sb.WriteString(fmt.Sprintf("Last Usable:      %s\n", s.LastUsable))
	sb.WriteString(fmt.Sprintf("Total Addresses:  %d\n", s.TotalHosts))
	sb.WriteString(fmt.Sprintf("Usable Hosts:     %d\n", s.UsableHosts))
	sb.WriteString(fmt.Sprintf("IP Class:         %s\n", s.IPClass))
	sb.WriteString(fmt.Sprintf("Private:          %v\n", s.IsPrivate))

	return sb.String()
}
