package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	command := os.Args[1]

	switch command {
	case "--version", "-v":
		fmt.Printf("nns version %s\n", version)
	case "--help", "-h", "help":
		printHelp()
	case "ping":
		fmt.Println("ping command - coming soon")
	case "traceroute":
		fmt.Println("traceroute command - coming soon")
	case "portscan":
		fmt.Println("portscan command - coming soon")
	case "bench":
		fmt.Println("bench command - coming soon")
	case "proxy":
		fmt.Println("proxy command - coming soon")
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	help := `NNS - Network Swiss Army Knife

A powerful networking toolkit for sysadmins and developers.

USAGE:
    nns [COMMAND] [OPTIONS]

COMMANDS:
    ping         Send ICMP echo requests to a host
    traceroute   Trace the network path to a host
    portscan     Scan ports on a target host or network
    bench        Benchmark HTTP endpoints
    proxy        Start a local debugging proxy server

OPTIONS:
    --version, -v    Show version information
    --help, -h       Show this help message

Use "nns [COMMAND] --help" for more information about a command.

EXAMPLES:
    nns ping google.com
    nns portscan 192.168.1.1 --ports 80,443
    nns bench https://api.example.com --requests 1000
    nns proxy --port 8080
`
	fmt.Print(help)
}
