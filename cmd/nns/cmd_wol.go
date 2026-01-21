package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/wol"
)

func runWOL(args []string) {
	fs := flag.NewFlagSet("wol", flag.ExitOnError)

	broadcastFlag := fs.String("broadcast", "255.255.255.255", "Broadcast address")
	portFlag := fs.Int("port", 9, "UDP port")
	interfaceFlag := fs.String("interface", "", "Network interface")

	// Short flags
	fs.StringVar(broadcastFlag, "b", "255.255.255.255", "Broadcast")
	fs.IntVar(portFlag, "p", 9, "Port")
	fs.StringVar(interfaceFlag, "i", "", "Interface")

	fs.Usage = func() {
		fmt.Println(`Usage: nns wol [MAC] [OPTIONS]

Wake-on-LAN - send magic packet to power on remote machines.

OPTIONS:
  -b, --broadcast   Broadcast address (default: 255.255.255.255)
  -p, --port        UDP port (default: 9)
  -i, --interface   Network interface to use
      --help        Show this help message

EXAMPLES:
  nns wol aa:bb:cc:dd:ee:ff
  nns wol aa:bb:cc:dd:ee:ff --broadcast 192.168.1.255
  nns wol aa:bb:cc:dd:ee:ff --interface eth0`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: MAC address required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	mac := fs.Arg(0)
	formattedMAC := wol.FormatMAC(mac)

	fmt.Printf("Sending Wake-on-LAN magic packet to %s...\n", formattedMAC)

	var err error
	if *interfaceFlag != "" {
		err = wol.WakeWithInterface(mac, *interfaceFlag, *portFlag)
	} else {
		err = wol.Wake(mac, *broadcastFlag, *portFlag)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Magic packet sent successfully!")
}
