package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JedizLaPulga/NNS/internal/proxy"
)

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	portFlag := fs.Int("port", 8080, "Port to listen on")
	verboseFlag := fs.Bool("verbose", false, "Log full request/response details")
	filterFlag := fs.String("filter", "", "Filter logs by domain/keyword")

	// Short flags
	fs.IntVar(portFlag, "p", 8080, "Port to listen on")
	fs.BoolVar(verboseFlag, "v", false, "Log full request/response details")

	fs.Usage = func() {
		fmt.Println(`Usage: nns proxy [OPTIONS]

Start a HTTP/HTTPS debug proxy server.

OPTIONS:
  -p, --port        Port to listen on (default: 8080)
  -v, --verbose     Log verbose details
      --filter      Filter logs by domain/keyword
      --help        Show this help message

EXAMPLES:
  nns proxy
  nns proxy -p 9090 -v
  nns proxy --filter google.com`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg := proxy.Config{
		Port:    *portFlag,
		Verbose: *verboseFlag,
		Filter:  *filterFlag,
	}

	p := proxy.NewProxy(cfg)
	if err := p.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Proxy error: %v\n", err)
		os.Exit(1)
	}
}
