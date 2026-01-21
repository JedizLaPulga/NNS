package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/JedizLaPulga/NNS/internal/interfaces"
)

func runInterfaces(args []string) {
	fs := flag.NewFlagSet("interfaces", flag.ExitOnError)

	activeFlag := fs.Bool("active", false, "Show only active (up) interfaces")
	nameFlag := fs.String("name", "", "Show specific interface by name")

	fs.BoolVar(activeFlag, "a", false, "Show only active interfaces")
	fs.StringVar(nameFlag, "n", "", "Interface name")

	fs.Usage = func() {
		fmt.Println(`Usage: nns interfaces [OPTIONS]

List network interfaces with detailed information.

OPTIONS:
  -a, --active      Show only active (up) interfaces
  -n, --name        Show specific interface by name
  --help            Show this help message

EXAMPLES:
  nns interfaces
  nns interfaces --active
  nns interfaces --name eth0`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	var ifaces []interfaces.Interface
	var err error

	if *nameFlag != "" {
		iface, err := interfaces.GetByName(*nameFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		ifaces = []interfaces.Interface{*iface}
	} else if *activeFlag {
		ifaces, err = interfaces.ListActive()
	} else {
		ifaces, err = interfaces.ListAll()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d interface(s)\n\n", len(ifaces))

	for _, iface := range ifaces {
		status := "DOWN"
		if iface.IsUp {
			status = "UP"
		}

		flags := []string{}
		if iface.IsLoopback {
			flags = append(flags, "loopback")
		}
		if iface.IsMulticast {
			flags = append(flags, "multicast")
		}
		if iface.IsBroadcast {
			flags = append(flags, "broadcast")
		}
		if interfaces.IsVirtual(iface) {
			flags = append(flags, "virtual")
		}

		fmt.Printf("%s [%s]:\n", iface.Name, status)
		fmt.Printf("  Index: %d, MTU: %d\n", iface.Index, iface.MTU)
		if iface.HardwareAddr != "" {
			fmt.Printf("  MAC: %s\n", iface.HardwareAddr)
		}
		if len(flags) > 0 {
			fmt.Printf("  Flags: %s\n", strings.Join(flags, ", "))
		}
		if len(iface.IPv4Addrs) > 0 {
			fmt.Printf("  IPv4: %s\n", strings.Join(iface.IPv4Addrs, ", "))
		}
		if len(iface.IPv6Addrs) > 0 {
			fmt.Printf("  IPv6: %s\n", strings.Join(iface.IPv6Addrs, ", "))
		}
		fmt.Println()
	}

	// Show default gateway interface
	if defIface, err := interfaces.GetDefaultGatewayInterface(); err == nil {
		fmt.Printf("Default Gateway Interface: %s\n", defIface.Name)
	}
}
