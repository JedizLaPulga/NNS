package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JedizLaPulga/NNS/internal/mqtt"
)

func runMQTT(args []string) {
	fs := flag.NewFlagSet("mqtt", flag.ExitOnError)
	port := fs.Int("port", 1883, "Broker port")
	useTLS := fs.Bool("tls", false, "Use TLS (MQTTS)")
	skipVerify := fs.Bool("insecure", false, "Skip TLS certificate verification")
	username := fs.String("user", "", "Username for authentication")
	password := fs.String("pass", "", "Password for authentication")
	clientID := fs.String("client-id", "nns-mqtt-check", "MQTT client ID")
	timeout := fs.Duration("timeout", 10*time.Second, "Connection timeout")
	pingCount := fs.Int("pings", 5, "Number of PINGREQ probes")
	brief := fs.Bool("brief", false, "Brief output")

	// Short flags
	fs.IntVar(port, "p", 1883, "Broker port")
	fs.BoolVar(useTLS, "s", false, "Use TLS (MQTTS)")
	fs.BoolVar(skipVerify, "k", false, "Skip TLS certificate verification")
	fs.StringVar(username, "u", "", "Username for authentication")
	fs.IntVar(pingCount, "c", 5, "Number of PINGREQ probes")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nns mqtt [options] <host>

Check MQTT broker connectivity, authentication, and latency.

Options:
  --port, -p         Broker port (default: 1883)
  --tls, -s          Use TLS (MQTTS, default port: 8883)
  --insecure, -k     Skip TLS certificate verification
  --user, -u         Username for authentication
  --pass             Password for authentication
  --client-id        MQTT client ID (default: nns-mqtt-check)
  --timeout          Connection timeout (default: 10s)
  --pings, -c        Number of PINGREQ probes (default: 5)
  --brief            Brief output
  --help             Show this help message

Examples:
  nns mqtt test.mosquitto.org
  nns mqtt broker.example.com -p 8883 --tls
  nns mqtt broker.example.com -u admin --pass secret
  nns mqtt broker.example.com --brief
`)
	}

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: broker host required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	host := fs.Arg(0)

	// Auto-set TLS port
	if *useTLS && *port == 1883 {
		*port = 8883
	}

	opts := mqtt.Options{
		Host:       host,
		Port:       *port,
		UseTLS:     *useTLS,
		SkipVerify: *skipVerify,
		Username:   *username,
		Password:   *password,
		ClientID:   *clientID,
		Timeout:    *timeout,
		PingCount:  *pingCount,
		Topics:     []string{"$SYS/#", "#", "test/nns"},
	}

	checker := mqtt.NewChecker(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	proto := "MQTT"
	if *useTLS {
		proto = "MQTTS"
	}
	fmt.Printf("Checking %s broker %s:%d...\n", proto, host, *port)

	result, err := checker.Check(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *brief {
		fmt.Println(result.FormatCompact())
	} else {
		fmt.Print(result.Format())
	}
}
