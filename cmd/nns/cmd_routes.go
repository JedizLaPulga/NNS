package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JedizLaPulga/NNS/internal/routes"
)

func runRoutes(args []string) {
	fs := flag.NewFlagSet("routes", flag.ExitOnError)
	filterFlag := fs.String("filter", "", "Filter routes by destination/gateway/interface")
	ifaceFlag := fs.String("interface", "", "Show routes for specific interface")
	defaultOnlyFlag := fs.Bool("default", false, "Show only default routes")
	ipv4OnlyFlag := fs.Bool("4", false, "Show IPv4 routes only")
	ipv6OnlyFlag := fs.Bool("6", false, "Show IPv6 routes only")
	testGatewayFlag := fs.Bool("test", false, "Test default gateway connectivity")
	jsonFlag := fs.Bool("json", false, "Output in JSON format")

	// Short flags
	fs.StringVar(filterFlag, "f", "", "Filter routes")
	fs.StringVar(ifaceFlag, "i", "", "Interface filter")
	fs.BoolVar(defaultOnlyFlag, "d", false, "Default routes only")

	fs.Usage = func() {
		fmt.Println(`Usage: nns routes [OPTIONS]

Display and analyze the system routing table.

OPTIONS:
  --filter, -f     Filter routes by destination/gateway/interface
  --interface, -i  Show routes for specific interface
  --default, -d    Show only default routes
  -4               Show IPv4 routes only
  -6               Show IPv6 routes only
  --test           Test default gateway connectivity
  --json           Output in JSON format
  --help           Show this help message

EXAMPLES:
  nns routes
  nns routes --default
  nns routes -f 192.168
  nns routes --interface eth0
  nns routes --test`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("System Routing Table")
	fmt.Println(strings.Repeat("─", 50))

	table, err := routes.GetRoutes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Apply filters
	displayRoutes := table.Routes

	if *filterFlag != "" {
		displayRoutes = table.Filter(*filterFlag)
	}

	if *ifaceFlag != "" {
		displayRoutes = table.GetInterfaceRoutes(*ifaceFlag)
	}

	if *defaultOnlyFlag {
		var defaultRoutes []routes.Route
		for _, r := range displayRoutes {
			if r.IsDefault {
				defaultRoutes = append(defaultRoutes, r)
			}
		}
		displayRoutes = defaultRoutes
	}

	if *jsonFlag {
		printRoutesJSON(table, displayRoutes)
		return
	}

	// Print summary
	fmt.Printf("\n📊 Summary: %s\n\n", table.Summary())

	// Default gateway info
	if table.DefaultGateway != "" {
		fmt.Printf("🌐 Default Gateway: %s via %s\n", table.DefaultGateway, table.DefaultIface)

		if *testGatewayFlag {
			fmt.Printf("\n🔍 Testing gateway connectivity...\n")
			gwInfo := routes.TestGateway(table.DefaultGateway, 5*time.Second)
			if gwInfo.Reachable {
				fmt.Printf("   ✅ Gateway reachable (RTT: %v)\n", gwInfo.RTT.Round(time.Millisecond))
			} else {
				fmt.Printf("   ❌ Gateway not reachable\n")
			}
			if gwInfo.Hostname != "" {
				fmt.Printf("   📛 Hostname: %s\n", gwInfo.Hostname)
			}
		}
	}

	// Print routes
	fmt.Printf("\n📋 Routes (%d):\n\n", len(displayRoutes))

	// Print header
	fmt.Printf("%-20s %-18s %-16s %-10s %s\n",
		"DESTINATION", "GATEWAY", "INTERFACE", "METRIC", "FLAGS")
	fmt.Println(strings.Repeat("-", 75))

	for _, r := range displayRoutes {
		// Skip based on IP version filter
		if *ipv4OnlyFlag && strings.Contains(r.Destination, ":") {
			continue
		}
		if *ipv6OnlyFlag && !strings.Contains(r.Destination, ":") {
			continue
		}

		dest := r.Destination
		if r.Netmask != "" && r.Netmask != "0.0.0.0" && r.Netmask != "255.255.255.255" {
			// dest += "/" + r.Netmask
		}

		gateway := r.Gateway
		if gateway == "" || gateway == "0.0.0.0" {
			gateway = "*"
		}

		flags := r.Flags
		if flags == "" {
			flags = buildFlags(r)
		}

		metric := fmt.Sprintf("%d", r.Metric)
		if r.Metric == 0 {
			metric = "-"
		}

		iface := r.Interface
		if iface == "" && r.InterfaceIndex > 0 {
			iface = fmt.Sprintf("if%d", r.InterfaceIndex)
		}

		fmt.Printf("%-20s %-18s %-16s %-10s %s\n",
			truncate(dest, 20),
			truncate(gateway, 18),
			truncate(iface, 16),
			metric,
			flags)
	}

	// Print counts
	fmt.Printf("\nIPv4: %d, IPv6: %d, Total: %d\n",
		table.IPv4Routes, table.IPv6Routes, len(table.Routes))
}

func buildFlags(r routes.Route) string {
	var flags []string
	if r.IsDefault {
		flags = append(flags, "D")
	}
	if r.IsHost {
		flags = append(flags, "H")
	}
	if r.Gateway != "" && r.Gateway != "0.0.0.0" {
		flags = append(flags, "G")
	}
	if len(flags) == 0 {
		return "U"
	}
	return "U" + strings.Join(flags, "")
}

func truncateRoute(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}

func printRoutesJSON(table *routes.RoutingTable, displayRoutes []routes.Route) {
	fmt.Printf(`{
  "default_gateway": "%s",
  "default_interface": "%s",
  "ipv4_routes": %d,
  "ipv6_routes": %d,
  "total_routes": %d,
  "displayed_routes": %d
}
`, table.DefaultGateway, table.DefaultIface,
		table.IPv4Routes, table.IPv6Routes,
		len(table.Routes), len(displayRoutes))
}
