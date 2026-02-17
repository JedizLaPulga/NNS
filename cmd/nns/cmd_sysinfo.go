package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/sysinfo"
)

func runSysinfo(args []string) {
	fs := flag.NewFlagSet("sysinfo", flag.ExitOnError)
	publicIP := fs.Bool("public", false, "Resolve public IP via OpenDNS")
	activeOnly := fs.Bool("active", false, "Show only active (up, non-loopback) interfaces")

	// Short flags
	fs.BoolVar(publicIP, "p", false, "Resolve public IP")
	fs.BoolVar(activeOnly, "a", false, "Active only")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns sysinfo [options]

Display system and network environment information including hostname,
OS, CPU count, network interfaces, local IPs, and optionally public IP.

Options:
  --public, -p     Resolve public IP via OpenDNS (requires internet)
  --active, -a     Show only active (up, non-loopback) interfaces
  --help           Show this help message

Examples:
  nns sysinfo
  nns sysinfo --public
  nns sysinfo --active
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := sysinfo.DefaultOptions()
	opts.ResolvePublic = *publicIP

	fmt.Printf("SYSTEM INFO\n\n")

	info := sysinfo.Collect(opts)

	if *activeOnly {
		var filtered []sysinfo.IfaceInfo
		for _, iface := range info.Interfaces {
			if iface.IsUp && !iface.IsLoopback {
				filtered = append(filtered, iface)
			}
		}
		info.Interfaces = filtered
	}

	fmt.Print(sysinfo.FormatInfo(info))
}
