// Package arp provides ARP table reading and MAC vendor lookup functionality.
package arp

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// Entry represents an ARP table entry.
type Entry struct {
	IP        string
	MAC       string
	Vendor    string
	Interface string
	Type      string // dynamic, static, etc.
}

// GetTable reads the system ARP table.
func GetTable() ([]Entry, error) {
	switch runtime.GOOS {
	case "windows":
		return getTableWindows()
	case "linux":
		return getTableLinux()
	case "darwin":
		return getTableDarwin()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getTableWindows reads ARP table on Windows using arp -a command.
func getTableWindows() ([]Entry, error) {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute arp -a: %w", err)
	}

	return parseWindowsARP(string(output))
}

// parseWindowsARP parses Windows arp -a output.
func parseWindowsARP(output string) ([]Entry, error) {
	entries := make([]Entry, 0)
	currentInterface := ""

	// Windows arp output format:
	// Interface: 192.168.1.100 --- 0x5
	//   Internet Address      Physical Address      Type
	//   192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic

	interfaceRe := regexp.MustCompile(`Interface:\s+(\S+)`)
	entryRe := regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// Check for interface line
		if matches := interfaceRe.FindStringSubmatch(line); len(matches) > 1 {
			currentInterface = matches[1]
			continue
		}

		// Check for entry line
		if matches := entryRe.FindStringSubmatch(line); len(matches) > 3 {
			mac := normalizeMACAddress(matches[2])
			if mac != "" && mac != "ff-ff-ff-ff-ff-ff" && mac != "00-00-00-00-00-00" {
				entry := Entry{
					IP:        matches[1],
					MAC:       mac,
					Type:      matches[3],
					Interface: currentInterface,
					Vendor:    LookupVendor(mac),
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries, nil
}

// getTableLinux reads ARP table on Linux from /proc/net/arp.
func getTableLinux() ([]Entry, error) {
	cmd := exec.Command("cat", "/proc/net/arp")
	output, err := cmd.Output()
	if err != nil {
		// Fall back to arp command
		cmd = exec.Command("arp", "-n")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to read ARP table: %w", err)
		}
		return parseLinuxARPCommand(string(output))
	}

	return parseLinuxProcARP(string(output))
}

// parseLinuxProcARP parses /proc/net/arp format.
func parseLinuxProcARP(output string) ([]Entry, error) {
	entries := make([]Entry, 0)

	// Format: IP address       HW type     Flags       HW address            Mask     Device
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip header
	if scanner.Scan() {
		// Header line skipped
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 6 {
			mac := normalizeMACAddress(fields[3])
			if mac != "" && mac != "00:00:00:00:00:00" {
				entry := Entry{
					IP:        fields[0],
					MAC:       mac,
					Interface: fields[5],
					Type:      "dynamic",
					Vendor:    LookupVendor(mac),
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries, nil
}

// parseLinuxARPCommand parses output from arp -n command.
func parseLinuxARPCommand(output string) ([]Entry, error) {
	entries := make([]Entry, 0)

	scanner := bufio.NewScanner(strings.NewReader(output))
	// Skip header
	if scanner.Scan() {
		// Header line skipped
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 {
			mac := normalizeMACAddress(fields[2])
			if mac != "" && mac != "00:00:00:00:00:00" {
				entry := Entry{
					IP:        fields[0],
					MAC:       mac,
					Interface: fields[4],
					Type:      fields[3],
					Vendor:    LookupVendor(mac),
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries, nil
}

// getTableDarwin reads ARP table on macOS.
func getTableDarwin() ([]Entry, error) {
	cmd := exec.Command("arp", "-an")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute arp -an: %w", err)
	}

	return parseDarwinARP(string(output))
}

// parseDarwinARP parses macOS arp -an output.
func parseDarwinARP(output string) ([]Entry, error) {
	entries := make([]Entry, 0)

	// Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
	entryRe := regexp.MustCompile(`\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+(\S+)`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if matches := entryRe.FindStringSubmatch(line); len(matches) > 3 {
			mac := normalizeMACAddress(matches[2])
			if mac != "" && mac != "ff:ff:ff:ff:ff:ff" {
				entry := Entry{
					IP:        matches[1],
					MAC:       mac,
					Interface: matches[3],
					Type:      "dynamic",
					Vendor:    LookupVendor(mac),
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries, nil
}

// normalizeMACAddress converts MAC to standard format (colon-separated).
func normalizeMACAddress(mac string) string {
	// Remove any incomplete entries
	if strings.Contains(mac, "(incomplete)") {
		return ""
	}

	// Replace - with : and lowercase
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	// Validate format
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return ""
	}

	// Pad each part if needed
	for i, part := range parts {
		if len(part) == 1 {
			parts[i] = "0" + part
		}
	}

	return strings.Join(parts, ":")
}

// FilterByInterface returns entries matching the specified interface.
func FilterByInterface(entries []Entry, iface string) []Entry {
	filtered := make([]Entry, 0)
	for _, e := range entries {
		if e.Interface == iface {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// GetInterfaces returns unique interface names from entries.
func GetInterfaces(entries []Entry) []string {
	seen := make(map[string]bool)
	ifaces := make([]string, 0)

	for _, e := range entries {
		if !seen[e.Interface] {
			seen[e.Interface] = true
			ifaces = append(ifaces, e.Interface)
		}
	}

	return ifaces
}
