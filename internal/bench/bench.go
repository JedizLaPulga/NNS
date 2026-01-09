// Package bench provides high-performance HTTP benchmarking functionality.
package bench

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"github.com/JedizLaPulga/NNS/internal/stats"
)

// Config holds configuration for the benchmark.
type Config struct {
	URL              string
	Method           string
	RequestCount     int
	Duration         time.Duration
	Concurrency      int
	Timeout          time.Duration
	QPS              float64
	DisableKeepAlive bool
	Body             io.Reader
	BodyFunc         func() io.Reader // Factory for creating body readers per request
	Headers          http.Header
}

// Result represents the outcome of a single request.
type Result struct {
	Duration   time.Duration
	DNS        time.Duration
	Connect    time.Duration
	TLS        time.Duration
	Wait       time.Duration // Time to First Byte (TTFB)
	Transfer   time.Duration
	StatusCode int
	Bytes      int64
	Error      error
}

// Summary holds the aggregated results of the benchmark.
type Summary struct {
	TotalRequests  int
	SuccessCount   int
	ErrorCount     int
	TotalDuration  time.Duration
	RequestsPerSec float64
	TransferRate   float64 // Read MB/s
	TotalReadBytes int64

	Latencies        []float64
	DNSLatencies     []float64
	ConnectLatencies []float64
	TLSLatencies     []float64
	WaitLatencies    []float64

	StatusCodes map[int]int
	Errors      map[string]int

	// Pre-calculated stats
	MinLat  time.Duration
	MeanLat time.Duration
	MaxLat  time.Duration
	P50Lat  time.Duration
	P90Lat  time.Duration
	P95Lat  time.Duration
	P99Lat  time.Duration

	// Component averages
	MeanDNS  time.Duration
	MeanConn time.Duration
	MeanTLS  time.Duration
	MeanWait time.Duration
}

// Run executes the benchmark.
func Run(ctx context.Context, cfg Config) *Summary {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}

	// Buffered channel to prevent blocking workers
	results := make(chan Result, cfg.Concurrency*100)
	var wg sync.WaitGroup

	startTime := time.Now()

	// Create client transport once
	tr := &http.Transport{
		MaxIdleConns:        cfg.Concurrency,
		MaxIdleConnsPerHost: cfg.Concurrency,
		DisableKeepAlives:   cfg.DisableKeepAlive,
		DisableCompression:  false,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
	}

	// Start workers
	workChan := make(chan struct{}, cfg.Concurrency)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Dispatcher
	go func() {
		defer close(workChan)

		if cfg.Duration > 0 {
			// Duration mode
			timer := time.NewTimer(cfg.Duration)
			defer timer.Stop()

			for {
				select {
				case <-timer.C:
					return
				case <-ctx.Done():
					return
				default:
					select {
					case workChan <- struct{}{}:
					case <-timer.C:
						return
					case <-ctx.Done():
						return
					}
				}
			}
		} else {
			// Request count mode
			count := cfg.RequestCount
			if count <= 0 {
				count = 1 // Default
			}
			for i := 0; i < count; i++ {
				select {
				case workChan <- struct{}{}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Workers
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range workChan {
				res := executeRequest(client, cfg)
				results <- res
			}
		}()
	}

	// Closer
	go func() {
		wg.Wait()
		close(results)
	}()

	// Aggregator
	summary := &Summary{
		StatusCodes:      make(map[int]int),
		Errors:           make(map[string]int),
		Latencies:        make([]float64, 0),
		DNSLatencies:     make([]float64, 0),
		ConnectLatencies: make([]float64, 0),
		TLSLatencies:     make([]float64, 0),
		WaitLatencies:    make([]float64, 0),
	}

	for res := range results {
		summary.TotalRequests++
		if res.Error != nil {
			summary.ErrorCount++
			summary.Errors[res.Error.Error()]++
		} else {
			summary.SuccessCount++
			summary.StatusCodes[res.StatusCode]++
			summary.TotalReadBytes += res.Bytes

			summary.Latencies = append(summary.Latencies, res.Duration.Seconds())
			summary.DNSLatencies = append(summary.DNSLatencies, res.DNS.Seconds())
			summary.ConnectLatencies = append(summary.ConnectLatencies, res.Connect.Seconds())
			summary.TLSLatencies = append(summary.TLSLatencies, res.TLS.Seconds())
			summary.WaitLatencies = append(summary.WaitLatencies, res.Wait.Seconds())
		}
	}

	summary.TotalDuration = time.Since(startTime)
	if summary.TotalDuration > 0 {
		summary.RequestsPerSec = float64(summary.TotalRequests) / summary.TotalDuration.Seconds()
		summary.TransferRate = float64(summary.TotalReadBytes) / 1024 / 1024 / summary.TotalDuration.Seconds()
	}

	summary.calculateStats()

	return summary
}

func executeRequest(client *http.Client, cfg Config) Result {
	var start, dnsStart, connStart, tlsStart, waitStart time.Time
	var dnsDur, connDur, tlsDur, waitDur time.Duration

	reqBody := cfg.Body
	if cfg.BodyFunc != nil {
		reqBody = cfg.BodyFunc()
	}

	req, err := http.NewRequest(cfg.Method, cfg.URL, reqBody)
	if err != nil {
		return Result{Error: err}
	}

	req.Header = cfg.Headers

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { dnsDur = time.Since(dnsStart) },

		ConnectStart: func(_, _ string) { connStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			connDur = time.Since(connStart)
		},

		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			tlsDur = time.Since(tlsStart)
		},

		WroteHeaders: func() { waitStart = time.Now() },
		GotFirstResponseByte: func() {
			waitDur = time.Since(waitStart)
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	start = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{Error: err, Duration: time.Since(start)}
	}
	defer resp.Body.Close()

	// Read full body to measure transfer time
	written, _ := io.Copy(io.Discard, resp.Body)
	totalDur := time.Since(start)

	transferDur := totalDur - dnsDur - connDur - tlsDur - waitDur
	if transferDur < 0 {
		transferDur = 0
	}

	return Result{
		Duration:   totalDur,
		DNS:        dnsDur,
		Connect:    connDur,
		TLS:        tlsDur,
		Wait:       waitDur,
		Transfer:   transferDur,
		StatusCode: resp.StatusCode,
		Bytes:      written,
	}
}

func (s *Summary) calculateStats() {
	if len(s.Latencies) == 0 {
		return
	}

	s.MinLat = time.Duration(stats.Percentile(s.Latencies, 0.0) * float64(time.Second))
	s.MaxLat = time.Duration(stats.Percentile(s.Latencies, 1.0) * float64(time.Second))
	s.MeanLat = time.Duration(stats.Mean(s.Latencies) * float64(time.Second))
	s.P50Lat = time.Duration(stats.Percentile(s.Latencies, 0.50) * float64(time.Second))
	s.P90Lat = time.Duration(stats.Percentile(s.Latencies, 0.90) * float64(time.Second))
	s.P95Lat = time.Duration(stats.Percentile(s.Latencies, 0.95) * float64(time.Second))
	s.P99Lat = time.Duration(stats.Percentile(s.Latencies, 0.99) * float64(time.Second))

	s.MeanDNS = time.Duration(stats.Mean(s.DNSLatencies) * float64(time.Second))
	s.MeanConn = time.Duration(stats.Mean(s.ConnectLatencies) * float64(time.Second))
	s.MeanTLS = time.Duration(stats.Mean(s.TLSLatencies) * float64(time.Second))
	s.MeanWait = time.Duration(stats.Mean(s.WaitLatencies) * float64(time.Second))
}
