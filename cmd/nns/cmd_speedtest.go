package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JedizLaPulga/NNS/internal/speedtest"
)

func runSpeedtest(args []string) {
	fs := flag.NewFlagSet("speedtest", flag.ExitOnError)

	urlFlag := fs.String("url", "", "Custom download URL for testing")
	timeoutFlag := fs.Duration("timeout", 60*time.Second, "Test timeout")

	fs.Usage = func() {
		fmt.Println(`Usage: nns speedtest [OPTIONS]

Perform a network speed test (download bandwidth).

OPTIONS:
  --url             Custom download URL for testing
  --timeout         Test timeout (default: 60s)
  --help            Show this help message

EXAMPLES:
  nns speedtest
  nns speedtest --url http://speedtest.example.com/100MB.bin`)
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	cfg := speedtest.DefaultConfig()
	if *urlFlag != "" {
		cfg.DownloadURL = *urlFlag
	}
	cfg.Timeout = *timeoutFlag

	tester := speedtest.NewTester(cfg)

	fmt.Println("Starting speed test...")
	fmt.Printf("Server: %s\n\n", cfg.DownloadURL)

	ctx := context.Background()

	result, err := tester.Run(ctx, func(stage string, progress float64) {
		switch stage {
		case "latency":
			fmt.Print("Testing latency... ")
		case "download":
			fmt.Printf("\rDownloading: %.0f%%", progress)
		case "complete":
			fmt.Println()
		}
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n--- Results ---")
	fmt.Printf("Latency:         %v\n", result.Latency)
	fmt.Printf("Download Speed:  %s\n", speedtest.FormatSpeed(result.DownloadSpeed))
	fmt.Printf("Downloaded:      %s in %v\n", speedtest.FormatBytes(result.DownloadBytes), result.DownloadTime.Round(time.Millisecond))

	if result.UploadSpeed > 0 {
		fmt.Printf("Upload Speed:    %s\n", speedtest.FormatSpeed(result.UploadSpeed))
	}
}
