// Package speedtest provides bandwidth testing functionality.
package speedtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Result holds the bandwidth test results.
type Result struct {
	DownloadSpeed float64       `json:"download_speed_mbps"`
	UploadSpeed   float64       `json:"upload_speed_mbps"`
	DownloadBytes int64         `json:"download_bytes"`
	UploadBytes   int64         `json:"upload_bytes"`
	DownloadTime  time.Duration `json:"download_time"`
	UploadTime    time.Duration `json:"upload_time"`
	Latency       time.Duration `json:"latency"`
	ServerURL     string        `json:"server_url"`
	Error         error         `json:"error,omitempty"`
}

// Config holds speedtest configuration.
type Config struct {
	DownloadURL  string        // URL for download test (should return large file)
	UploadURL    string        // URL for upload test (should accept POST)
	DownloadSize int64         // Expected download size in bytes
	UploadSize   int64         // Size to upload in bytes
	Timeout      time.Duration // Overall timeout
	Connections  int           // Number of parallel connections
}

// DefaultConfig returns sensible defaults using public test endpoints.
func DefaultConfig() Config {
	return Config{
		DownloadURL:  "http://speedtest.tele2.net/10MB.zip",
		UploadURL:    "",               // Upload test requires a server that accepts uploads
		DownloadSize: 10 * 1024 * 1024, // 10 MB
		UploadSize:   5 * 1024 * 1024,  // 5 MB
		Timeout:      60 * time.Second,
		Connections:  4,
	}
}

// Tester performs bandwidth tests.
type Tester struct {
	cfg    Config
	client *http.Client
}

// NewTester creates a new Tester.
func NewTester(cfg Config) *Tester {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.Connections <= 0 {
		cfg.Connections = 4
	}

	return &Tester{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        cfg.Connections * 2,
				MaxIdleConnsPerHost: cfg.Connections * 2,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

// Run performs the full bandwidth test.
func (t *Tester) Run(ctx context.Context, callback func(stage string, progress float64)) (*Result, error) {
	result := &Result{
		ServerURL: t.cfg.DownloadURL,
	}

	// Test latency first
	if callback != nil {
		callback("latency", 0)
	}
	latency, err := t.testLatency(ctx)
	if err != nil {
		result.Error = fmt.Errorf("latency test failed: %w", err)
		return result, err
	}
	result.Latency = latency

	// Download test
	if t.cfg.DownloadURL != "" {
		if callback != nil {
			callback("download", 0)
		}
		dlBytes, dlTime, err := t.testDownload(ctx, func(p float64) {
			if callback != nil {
				callback("download", p)
			}
		})
		if err != nil {
			result.Error = fmt.Errorf("download test failed: %w", err)
			return result, err
		}
		result.DownloadBytes = dlBytes
		result.DownloadTime = dlTime
		result.DownloadSpeed = bytesToMbps(dlBytes, dlTime)
	}

	// Upload test (if configured)
	if t.cfg.UploadURL != "" {
		if callback != nil {
			callback("upload", 0)
		}
		ulBytes, ulTime, err := t.testUpload(ctx, func(p float64) {
			if callback != nil {
				callback("upload", p)
			}
		})
		if err != nil {
			result.Error = fmt.Errorf("upload test failed: %w", err)
			return result, err
		}
		result.UploadBytes = ulBytes
		result.UploadTime = ulTime
		result.UploadSpeed = bytesToMbps(ulBytes, ulTime)
	}

	if callback != nil {
		callback("complete", 100)
	}

	return result, nil
}

func (t *Tester) testLatency(ctx context.Context) (time.Duration, error) {
	if t.cfg.DownloadURL == "" {
		return 0, fmt.Errorf("no download URL configured")
	}

	// Make a HEAD request to measure latency
	req, err := http.NewRequestWithContext(ctx, "HEAD", t.cfg.DownloadURL, nil)
	if err != nil {
		return 0, err
	}

	// Average of 3 attempts
	var total time.Duration
	attempts := 3

	for i := 0; i < attempts; i++ {
		start := time.Now()
		resp, err := t.client.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		total += time.Since(start)
	}

	return total / time.Duration(attempts), nil
}

func (t *Tester) testDownload(ctx context.Context, progress func(float64)) (int64, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", t.cfg.DownloadURL, nil)
	if err != nil {
		return 0, 0, err
	}

	start := time.Now()
	resp, err := t.client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	// Read and discard data, tracking progress
	var totalBytes int64
	expectedSize := t.cfg.DownloadSize
	if resp.ContentLength > 0 {
		expectedSize = resp.ContentLength
	}

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		select {
		case <-ctx.Done():
			return totalBytes, time.Since(start), ctx.Err()
		default:
		}

		n, err := resp.Body.Read(buf)
		totalBytes += int64(n)

		if progress != nil && expectedSize > 0 {
			progress(float64(totalBytes) / float64(expectedSize) * 100)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return totalBytes, time.Since(start), err
		}
	}

	return totalBytes, time.Since(start), nil
}

func (t *Tester) testUpload(ctx context.Context, progress func(float64)) (int64, time.Duration, error) {
	// Create a reader that generates random data
	data := make([]byte, t.cfg.UploadSize)
	_, err := rand.Read(data)
	if err != nil {
		// Fallback to zeros
		for i := range data {
			data[i] = byte(i % 256)
		}
	}

	reader := &progressReader{
		reader: io.NopCloser(io.NewSectionReader(
			&bytesReaderAt{data: data}, 0, int64(len(data)))),
		total:    int64(len(data)),
		progress: progress,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.cfg.UploadURL, reader)
	if err != nil {
		return 0, 0, err
	}
	req.ContentLength = int64(len(data))
	req.Header.Set("Content-Type", "application/octet-stream")

	start := time.Now()
	resp, err := t.client.Do(req)
	if err != nil {
		return int64(len(data)), time.Since(start), err
	}
	defer resp.Body.Close()

	return int64(len(data)), time.Since(start), nil
}

// TestDownloadOnly performs only the download test.
func (t *Tester) TestDownloadOnly(ctx context.Context) (float64, error) {
	bytes, duration, err := t.testDownload(ctx, nil)
	if err != nil {
		return 0, err
	}
	return bytesToMbps(bytes, duration), nil
}

// TestLatencyOnly measures just the latency.
func (t *Tester) TestLatencyOnly(ctx context.Context) (time.Duration, error) {
	return t.testLatency(ctx)
}

func bytesToMbps(bytes int64, duration time.Duration) float64 {
	if duration <= 0 {
		return 0
	}
	bits := float64(bytes) * 8
	seconds := duration.Seconds()
	return bits / seconds / 1_000_000 // Mbps
}

// FormatSpeed formats a speed in Mbps to a human-readable string.
func FormatSpeed(mbps float64) string {
	if mbps >= 1000 {
		return fmt.Sprintf("%.2f Gbps", mbps/1000)
	}
	return fmt.Sprintf("%.2f Mbps", mbps)
}

// FormatBytes formats bytes to human-readable.
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// progressReader wraps a reader to track progress.
type progressReader struct {
	reader   io.ReadCloser
	total    int64
	read     int64
	progress func(float64)
	mu       sync.Mutex
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.mu.Lock()
	pr.read += int64(n)
	if pr.progress != nil && pr.total > 0 {
		pr.progress(float64(pr.read) / float64(pr.total) * 100)
	}
	pr.mu.Unlock()
	return n, err
}

func (pr *progressReader) Close() error {
	return pr.reader.Close()
}

// bytesReaderAt implements io.ReaderAt for a byte slice.
type bytesReaderAt struct {
	data []byte
}

func (b *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n = copy(p, b.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return
}

// QuickTest performs a quick single-connection download test.
func QuickTest(ctx context.Context, url string) (*Result, error) {
	cfg := Config{
		DownloadURL: url,
		Timeout:     30 * time.Second,
		Connections: 1,
	}
	tester := NewTester(cfg)
	return tester.Run(ctx, nil)
}

// EstimateDuration estimates how long a test will take based on connection speed.
func EstimateDuration(estimatedMbps float64, downloadSizeMB int64) time.Duration {
	if estimatedMbps <= 0 {
		return 30 * time.Second // Default estimate
	}
	// Time = Size (bits) / Speed (bits/sec)
	sizeBits := float64(downloadSizeMB) * 8 * 1_000_000
	speedBps := estimatedMbps * 1_000_000
	seconds := sizeBits / speedBps
	return time.Duration(seconds * float64(time.Second))
}
