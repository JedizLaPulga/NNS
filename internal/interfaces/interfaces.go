// Package interfaces provides network interface information and statistics.
package interfaces

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
)

// Interface represents a network interface with detailed information.
type Interface struct {
	Name         string   `json:"name"`
	Index        int      `json:"index"`
	MTU          int      `json:"mtu"`
	Flags        string   `json:"flags"`
	HardwareAddr string   `json:"hardware_addr"`
	IPv4Addrs    []string `json:"ipv4_addresses"`
	IPv6Addrs    []string `json:"ipv6_addresses"`
	IsUp         bool     `json:"is_up"`
	IsLoopback   bool     `json:"is_loopback"`
	IsP2P        bool     `json:"is_point_to_point"`
	IsMulticast  bool     `json:"is_multicast"`
	IsBroadcast  bool     `json:"is_broadcast"`
}

// Stats holds interface statistics (platform-dependent).
type Stats struct {
	BytesSent     uint64 `json:"bytes_sent"`
	BytesRecv     uint64 `json:"bytes_recv"`
	PacketsSent   uint64 `json:"packets_sent"`
	PacketsRecv   uint64 `json:"packets_recv"`
	ErrorsIn      uint64 `json:"errors_in"`
	ErrorsOut     uint64 `json:"errors_out"`
	DropsIn       uint64 `json:"drops_in"`
	DropsOut      uint64 `json:"drops_out"`
	Available     bool   `json:"available"`
	InterfaceName string `json:"interface_name"`
}

// ListAll returns all network interfaces with their information.
func ListAll() ([]Interface, error) {
	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	interfaces := make([]Interface, 0, len(netIfaces))

	for _, iface := range netIfaces {
		info := Interface{
			Name:         iface.Name,
			Index:        iface.Index,
			MTU:          iface.MTU,
			Flags:        iface.Flags.String(),
			HardwareAddr: iface.HardwareAddr.String(),
			IPv4Addrs:    make([]string, 0),
			IPv6Addrs:    make([]string, 0),
			IsUp:         iface.Flags&net.FlagUp != 0,
			IsLoopback:   iface.Flags&net.FlagLoopback != 0,
			IsP2P:        iface.Flags&net.FlagPointToPoint != 0,
			IsMulticast:  iface.Flags&net.FlagMulticast != 0,
			IsBroadcast:  iface.Flags&net.FlagBroadcast != 0,
		}

		// Get addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				if ipNet.IP.To4() != nil {
					info.IPv4Addrs = append(info.IPv4Addrs, addr.String())
				} else {
					info.IPv6Addrs = append(info.IPv6Addrs, addr.String())
				}
			}
		}

		interfaces = append(interfaces, info)
	}

	// Sort by index
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Index < interfaces[j].Index
	})

	return interfaces, nil
}

// ListActive returns only active (up) interfaces.
func ListActive() ([]Interface, error) {
	all, err := ListAll()
	if err != nil {
		return nil, err
	}

	active := make([]Interface, 0)
	for _, iface := range all {
		if iface.IsUp {
			active = append(active, iface)
		}
	}
	return active, nil
}

// GetByName returns a specific interface by name.
func GetByName(name string) (*Interface, error) {
	all, err := ListAll()
	if err != nil {
		return nil, err
	}

	for _, iface := range all {
		if strings.EqualFold(iface.Name, name) {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("interface %q not found", name)
}

// GetDefaultGatewayInterface attempts to find the interface used for default route.
func GetDefaultGatewayInterface() (*Interface, error) {
	// Try to find interface with default route by connecting to external address
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, fmt.Errorf("failed to determine default interface: %w", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	all, err := ListAll()
	if err != nil {
		return nil, err
	}

	for _, iface := range all {
		for _, addr := range iface.IPv4Addrs {
			if strings.HasPrefix(addr, localAddr.IP.String()) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("could not find default interface")
}

// GetPlatform returns the current OS.
func GetPlatform() string {
	return runtime.GOOS
}

// FormatInterface returns a formatted string representation of an interface.
func FormatInterface(iface Interface) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s (index %d):\n", iface.Name, iface.Index))
	sb.WriteString(fmt.Sprintf("  Flags: %s\n", iface.Flags))
	sb.WriteString(fmt.Sprintf("  MTU: %d\n", iface.MTU))

	if iface.HardwareAddr != "" {
		sb.WriteString(fmt.Sprintf("  MAC: %s\n", iface.HardwareAddr))
	}

	if len(iface.IPv4Addrs) > 0 {
		sb.WriteString("  IPv4:\n")
		for _, addr := range iface.IPv4Addrs {
			sb.WriteString(fmt.Sprintf("    %s\n", addr))
		}
	}

	if len(iface.IPv6Addrs) > 0 {
		sb.WriteString("  IPv6:\n")
		for _, addr := range iface.IPv6Addrs {
			sb.WriteString(fmt.Sprintf("    %s\n", addr))
		}
	}

	return sb.String()
}

// GetInterfaceCount returns the total number of interfaces.
func GetInterfaceCount() (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	return len(ifaces), nil
}

// HasIPv6 checks if any interface has IPv6 addresses.
func HasIPv6() (bool, error) {
	ifaces, err := ListAll()
	if err != nil {
		return false, err
	}

	for _, iface := range ifaces {
		if len(iface.IPv6Addrs) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// GetLocalIPs returns all local IP addresses.
func GetLocalIPs() ([]string, error) {
	ifaces, err := ListAll()
	if err != nil {
		return nil, err
	}

	ips := make([]string, 0)
	for _, iface := range ifaces {
		for _, addr := range iface.IPv4Addrs {
			// Extract just the IP without CIDR
			ip, _, _ := net.ParseCIDR(addr)
			if ip != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips, nil
}

// IsVirtual attempts to detect if an interface is virtual (heuristic).
func IsVirtual(iface Interface) bool {
	name := strings.ToLower(iface.Name)
	virtualPrefixes := []string{
		"veth", "docker", "br-", "virbr", "vbox", "vmnet",
		"tap", "tun", "wg", "tailscale", "utun",
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
