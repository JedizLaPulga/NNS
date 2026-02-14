// Package cidrmerge provides CIDR aggregation, deduplication, and consolidation utilities.
package cidrmerge

import (
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
)

// MergeResult holds the result of a CIDR merge operation.
type MergeResult struct {
	Input       []string `json:"input"`
	Output      []string `json:"output"`
	InputCount  int      `json:"input_count"`
	OutputCount int      `json:"output_count"`
	Reduced     int      `json:"reduced"`
	Invalid     []string `json:"invalid,omitempty"`
}

// Merge takes a list of CIDR strings and produces a minimal list of CIDRs
// that covers exactly the same IP space. It removes duplicates, merges
// adjacent/overlapping prefixes, and consolidates contained ranges.
func Merge(cidrs []string) MergeResult {
	result := MergeResult{
		Input:      cidrs,
		InputCount: len(cidrs),
	}

	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try adding /32 or /128 for bare IPs
			ip := net.ParseIP(cidr)
			if ip != nil {
				if ip.To4() != nil {
					_, n, _ = net.ParseCIDR(cidr + "/32")
				} else {
					_, n, _ = net.ParseCIDR(cidr + "/128")
				}
				nets = append(nets, n)
				continue
			}
			result.Invalid = append(result.Invalid, cidr)
			continue
		}
		nets = append(nets, n)
	}

	merged := mergeNets(nets)
	for _, n := range merged {
		result.Output = append(result.Output, n.String())
	}

	result.OutputCount = len(result.Output)
	result.Reduced = result.InputCount - result.OutputCount - len(result.Invalid)
	if result.Reduced < 0 {
		result.Reduced = 0
	}

	return result
}

// Contains checks if a CIDR contains a given IP address.
func Contains(cidr string, ip string) (bool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR: %s", cidr)
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP: %s", ip)
	}

	return network.Contains(parsedIP), nil
}

// Overlaps checks if two CIDRs overlap.
func Overlaps(a, b string) (bool, error) {
	_, netA, err := net.ParseCIDR(a)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR: %s", a)
	}
	_, netB, err := net.ParseCIDR(b)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR: %s", b)
	}

	return netA.Contains(netB.IP) || netB.Contains(netA.IP), nil
}

// Exclude removes a CIDR range from another, returning the remaining ranges.
func Exclude(base, exclude string) ([]string, error) {
	_, baseNet, err := net.ParseCIDR(base)
	if err != nil {
		return nil, fmt.Errorf("invalid base CIDR: %s", base)
	}
	_, exclNet, err := net.ParseCIDR(exclude)
	if err != nil {
		return nil, fmt.Errorf("invalid exclude CIDR: %s", exclude)
	}

	if !baseNet.Contains(exclNet.IP) {
		return []string{baseNet.String()}, nil
	}

	remaining := excludeNet(baseNet, exclNet)
	var result []string
	for _, n := range remaining {
		result = append(result, n.String())
	}
	return result, nil
}

// HostCount returns the number of usable host addresses in a CIDR.
func HostCount(cidr string) (*big.Int, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", cidr)
	}

	ones, bits := network.Mask.Size()
	hostBits := bits - ones

	count := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))

	// For IPv4 /31 and /32, all addresses are usable; otherwise subtract 2
	if bits == 32 && hostBits > 1 {
		count.Sub(count, big.NewInt(2))
	}

	return count, nil
}

// FormatResult returns a human-readable string for the merge result.
func FormatResult(r MergeResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Input CIDRs:  %d\n", r.InputCount))
	sb.WriteString(fmt.Sprintf("  Output CIDRs: %d\n", r.OutputCount))
	sb.WriteString(fmt.Sprintf("  Reduced by:   %d\n", r.Reduced))

	if len(r.Invalid) > 0 {
		sb.WriteString(fmt.Sprintf("  Invalid:      %s\n", strings.Join(r.Invalid, ", ")))
	}

	sb.WriteString("\n  Merged prefixes:\n")
	for _, cidr := range r.Output {
		count, err := HostCount(cidr)
		if err == nil {
			sb.WriteString(fmt.Sprintf("    %-20s (%s hosts)\n", cidr, count.String()))
		} else {
			sb.WriteString(fmt.Sprintf("    %s\n", cidr))
		}
	}

	return sb.String()
}

// mergeNets performs the actual merge of IPNet slices.
func mergeNets(nets []*net.IPNet) []*net.IPNet {
	if len(nets) == 0 {
		return nil
	}

	// Separate IPv4 and IPv6
	var v4, v6 []*net.IPNet
	for _, n := range nets {
		if n.IP.To4() != nil {
			v4 = append(v4, n)
		} else {
			v6 = append(v6, n)
		}
	}

	merged := mergeFamily(v4)
	merged = append(merged, mergeFamily(v6)...)
	return merged
}

func mergeFamily(nets []*net.IPNet) []*net.IPNet {
	if len(nets) == 0 {
		return nil
	}

	// Sort by IP, then by prefix length (shorter first)
	sort.Slice(nets, func(i, j int) bool {
		cmp := compareIP(nets[i].IP, nets[j].IP)
		if cmp != 0 {
			return cmp < 0
		}
		oi, _ := nets[i].Mask.Size()
		oj, _ := nets[j].Mask.Size()
		return oi < oj
	})

	// Remove contained duplicates
	deduped := dedup(nets)

	// Merge adjacent siblings
	for {
		merged := mergeSiblings(deduped)
		if len(merged) == len(deduped) {
			return merged
		}
		deduped = merged
	}
}

// dedup removes CIDRs that are contained within a larger CIDR.
func dedup(sorted []*net.IPNet) []*net.IPNet {
	var result []*net.IPNet
	for _, n := range sorted {
		contained := false
		for _, existing := range result {
			if existing.Contains(n.IP) && contains(existing, n) {
				contained = true
				break
			}
		}
		if !contained {
			result = append(result, n)
		}
	}
	return result
}

// mergeSiblings merges adjacent sibling CIDRs.
func mergeSiblings(nets []*net.IPNet) []*net.IPNet {
	var result []*net.IPNet
	used := make([]bool, len(nets))

	for i := 0; i < len(nets); i++ {
		if used[i] {
			continue
		}
		merged := false
		for j := i + 1; j < len(nets); j++ {
			if used[j] {
				continue
			}
			parent := areSiblings(nets[i], nets[j])
			if parent != nil {
				result = append(result, parent)
				used[i] = true
				used[j] = true
				merged = true
				break
			}
		}
		if !merged {
			result = append(result, nets[i])
		}
	}

	return result
}

// areSiblings checks if two CIDRs are adjacent siblings that can be merged.
func areSiblings(a, b *net.IPNet) *net.IPNet {
	onesA, bitsA := a.Mask.Size()
	onesB, bitsB := b.Mask.Size()

	if onesA != onesB || bitsA != bitsB {
		return nil
	}
	if onesA == 0 {
		return nil
	}

	// Parent would be one bit shorter
	parentOnes := onesA - 1
	parentMask := net.CIDRMask(parentOnes, bitsA)

	parentA := a.IP.Mask(parentMask)
	parentB := b.IP.Mask(parentMask)

	if !parentA.Equal(parentB) {
		return nil
	}

	return &net.IPNet{
		IP:   parentA,
		Mask: parentMask,
	}
}

// contains checks if network a fully contains network b.
func contains(a, b *net.IPNet) bool {
	onesA, _ := a.Mask.Size()
	onesB, _ := b.Mask.Size()
	return onesA <= onesB && a.Contains(b.IP)
}

func compareIP(a, b net.IP) int {
	a16 := a.To16()
	b16 := b.To16()
	if a16 == nil || b16 == nil {
		return 0
	}
	for i := 0; i < len(a16); i++ {
		if a16[i] < b16[i] {
			return -1
		}
		if a16[i] > b16[i] {
			return 1
		}
	}
	return 0
}

func excludeNet(base, exclude *net.IPNet) []*net.IPNet {
	onesBase, bitsBase := base.Mask.Size()
	onesExcl, _ := exclude.Mask.Size()

	if onesExcl <= onesBase {
		return nil
	}

	var result []*net.IPNet
	current := base

	for prefixLen := onesBase + 1; prefixLen <= onesExcl; prefixLen++ {
		mask := net.CIDRMask(prefixLen, bitsBase)
		// The "other half" that doesn't contain the excluded range
		halfIP := make(net.IP, len(current.IP))
		copy(halfIP, current.IP)

		// Split: one half contains exclude, the other doesn't
		// Check which half contains the exclusion
		low := &net.IPNet{IP: current.IP.Mask(mask), Mask: mask}

		if low.Contains(exclude.IP) {
			// The excluded range is in the low half; keep the high half
			highIP := flipBit(current.IP, prefixLen-1, bitsBase)
			highNet := &net.IPNet{IP: highIP.Mask(mask), Mask: mask}
			result = append(result, highNet)
			current = low
		} else {
			// The excluded range is in the high half; keep the low half
			result = append(result, low)
			highIP := flipBit(current.IP, prefixLen-1, bitsBase)
			highNet := &net.IPNet{IP: highIP.Mask(mask), Mask: mask}
			current = highNet
		}
	}

	return result
}

func flipBit(ip net.IP, bit, bits int) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	if bits == 32 {
		result = result.To4()
		if result == nil {
			return ip
		}
	} else {
		result = result.To16()
	}

	byteIndex := bit / 8
	bitIndex := uint(7 - (bit % 8))
	result[byteIndex] ^= 1 << bitIndex

	return result
}
