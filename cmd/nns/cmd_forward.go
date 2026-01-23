package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/JedizLaPulga/NNS/internal/portforward"
)

func runPortForward(args []string) {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	localAddr := fs.String("l", "127.0.0.1:8080", "Local address to listen on")
	timeout := fs.Duration("t", 10*time.Second, "Connection timeout")
	bufSize := fs.Int("buf", 32, "Buffer size in KB")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nns forward [options] <remote_host:port>\n\n")
		fmt.Fprintf(os.Stderr, "TCP port forwarding / tunnel.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  nns forward -l 127.0.0.1:8080 example.com:80\n")
		fmt.Fprintf(os.Stderr, "  nns forward -l :3000 localhost:3001\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	remoteAddr := fs.Arg(0)

	cfg := portforward.Config{
		LocalAddr:   *localAddr,
		RemoteAddr:  remoteAddr,
		DialTimeout: *timeout,
		BufferSize:  *bufSize * 1024,
	}

	fwd, err := portforward.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fwd.OnConnect(func(client, remote string) {
		fmt.Printf("[+] %s -> %s\n", client, remote)
	})
	fwd.OnDisconnect(func(client string, dur time.Duration, sent, recv uint64) {
		fmt.Printf("[-] %s (%.1fs, ↑%s ↓%s)\n", client, dur.Seconds(),
			portforward.FormatBytes(sent), portforward.FormatBytes(recv))
	})
	fwd.OnError(func(client string, err error) {
		fmt.Fprintf(os.Stderr, "[!] %s: %v\n", client, err)
	})

	fmt.Printf("Forwarding %s -> %s\n", *localAddr, remoteAddr)
	fmt.Println("Press Ctrl+C to stop\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		fwd.Stop()
		cancel()
	}()

	if err := fwd.Start(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println(portforward.FormatStats(fwd.Stats()))
}
