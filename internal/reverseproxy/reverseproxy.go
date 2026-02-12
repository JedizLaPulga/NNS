// Package reverseproxy provides an HTTP/HTTPS reverse proxy with request logging and statistics.
package reverseproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// RequestLog represents a single proxied request.
type RequestLog struct {
	Timestamp  time.Time
	Method     string
	Path       string
	StatusCode int
	Latency    time.Duration
	ClientAddr string
	BytesSent  int64
	Error      error
}

// Statistics holds aggregate proxy statistics.
type Statistics struct {
	mu           sync.Mutex
	TotalReqs    int
	SuccessReqs  int
	FailedReqs   int
	BytesSent    int64
	MinLatency   time.Duration
	MaxLatency   time.Duration
	AvgLatency   time.Duration
	MedianLat    time.Duration
	P95Latency   time.Duration
	P99Latency   time.Duration
	StatusCounts map[int]int
	MethodCounts map[string]int
	StartTime    time.Time
	allLatencies []time.Duration
}

// NewStatistics creates an initialized Statistics.
func NewStatistics() *Statistics {
	return &Statistics{
		StatusCounts: make(map[int]int),
		MethodCounts: make(map[string]int),
		StartTime:    time.Now(),
		allLatencies: make([]time.Duration, 0, 64),
	}
}

// Record adds a request log entry.
func (s *Statistics) Record(log RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalReqs++
	s.MethodCounts[log.Method]++

	if log.Error != nil {
		s.FailedReqs++
		return
	}

	s.SuccessReqs++
	s.BytesSent += log.BytesSent
	s.StatusCounts[log.StatusCode]++
	s.allLatencies = append(s.allLatencies, log.Latency)

	if s.MinLatency == 0 || log.Latency < s.MinLatency {
		s.MinLatency = log.Latency
	}
	if log.Latency > s.MaxLatency {
		s.MaxLatency = log.Latency
	}
}

// Calculate computes aggregate statistics.
func (s *Statistics) Calculate() {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.allLatencies)
	if n == 0 {
		return
	}

	sorted := make([]time.Duration, n)
	copy(sorted, s.allLatencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	s.AvgLatency = total / time.Duration(n)
	s.MedianLat = sorted[n/2]

	p95Idx := int(math.Ceil(float64(n)*0.95)) - 1
	if p95Idx < 0 {
		p95Idx = 0
	}
	if p95Idx >= n {
		p95Idx = n - 1
	}
	s.P95Latency = sorted[p95Idx]

	p99Idx := int(math.Ceil(float64(n)*0.99)) - 1
	if p99Idx < 0 {
		p99Idx = 0
	}
	if p99Idx >= n {
		p99Idx = n - 1
	}
	s.P99Latency = sorted[p99Idx]
}

// Snapshot returns a copy for safe reading.
func (s *Statistics) Snapshot() Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s
	cp.StatusCounts = make(map[int]int)
	for k, v := range s.StatusCounts {
		cp.StatusCounts[k] = v
	}
	cp.MethodCounts = make(map[string]int)
	for k, v := range s.MethodCounts {
		cp.MethodCounts[k] = v
	}
	return cp
}

// Format returns a human-readable statistics summary.
func (s *Statistics) Format() string {
	s.Calculate()
	snap := s.Snapshot()

	var b strings.Builder
	uptime := time.Since(snap.StartTime).Round(time.Second)
	rps := float64(0)
	if uptime.Seconds() > 0 {
		rps = float64(snap.TotalReqs) / uptime.Seconds()
	}

	b.WriteString("\n╔══════════════════════════════════════════╗\n")
	b.WriteString("║       REVERSE PROXY STATISTICS           ║\n")
	b.WriteString("╚══════════════════════════════════════════╝\n\n")

	b.WriteString(fmt.Sprintf("  Uptime:      %v\n", uptime))
	b.WriteString(fmt.Sprintf("  Requests:    %d total, %d success, %d failed\n",
		snap.TotalReqs, snap.SuccessReqs, snap.FailedReqs))
	b.WriteString(fmt.Sprintf("  Throughput:  %.1f req/s\n", rps))
	b.WriteString(fmt.Sprintf("  Bytes sent:  %s\n\n", formatBytes(snap.BytesSent)))

	if snap.SuccessReqs > 0 {
		b.WriteString("  Latency:\n")
		b.WriteString(fmt.Sprintf("    Min:    %v\n", snap.MinLatency.Round(time.Microsecond)))
		b.WriteString(fmt.Sprintf("    Avg:    %v\n", snap.AvgLatency.Round(time.Microsecond)))
		b.WriteString(fmt.Sprintf("    Median: %v\n", snap.MedianLat.Round(time.Microsecond)))
		b.WriteString(fmt.Sprintf("    P95:    %v\n", snap.P95Latency.Round(time.Microsecond)))
		b.WriteString(fmt.Sprintf("    P99:    %v\n", snap.P99Latency.Round(time.Microsecond)))
		b.WriteString(fmt.Sprintf("    Max:    %v\n\n", snap.MaxLatency.Round(time.Microsecond)))
	}

	if len(snap.StatusCounts) > 0 {
		b.WriteString("  Status codes:\n")
		codes := make([]int, 0, len(snap.StatusCounts))
		for c := range snap.StatusCounts {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			b.WriteString(fmt.Sprintf("    %d: %d\n", c, snap.StatusCounts[c]))
		}
		b.WriteString("\n")
	}

	if len(snap.MethodCounts) > 0 {
		b.WriteString("  Methods:\n")
		methods := make([]string, 0, len(snap.MethodCounts))
		for m := range snap.MethodCounts {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		for _, m := range methods {
			b.WriteString(fmt.Sprintf("    %s: %d\n", m, snap.MethodCounts[m]))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// HeaderRule defines a header to inject or strip.
type HeaderRule struct {
	Name   string
	Value  string
	Remove bool
}

// Options configures the reverse proxy.
type Options struct {
	ListenAddr  string
	BackendURL  string
	Headers     []HeaderRule
	Timeout     time.Duration
	SkipVerify  bool
	LogRequests bool
	OnRequest   func(RequestLog)
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		ListenAddr:  ":8080",
		Timeout:     30 * time.Second,
		LogRequests: true,
	}
}

// Proxy is an HTTP reverse proxy with request logging.
type Proxy struct {
	opts    Options
	backend *url.URL
	Stats   *Statistics
	server  *http.Server
}

// NewProxy creates a new reverse proxy.
func NewProxy(opts Options) (*Proxy, error) {
	if opts.BackendURL == "" {
		return nil, fmt.Errorf("backend URL required")
	}
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":8080"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}

	backend, err := url.Parse(opts.BackendURL)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL: %w", err)
	}
	if backend.Scheme == "" || backend.Host == "" {
		return nil, fmt.Errorf("backend URL must include scheme and host (e.g. http://localhost:3000)")
	}

	return &Proxy{
		opts:    opts,
		backend: backend,
		Stats:   NewStatistics(),
	}, nil
}

// ListenAddr returns the configured listen address.
func (p *Proxy) ListenAddr() string {
	return p.opts.ListenAddr
}

// BackendURL returns the parsed backend URL.
func (p *Proxy) BackendURL() *url.URL {
	return p.backend
}

// statusRecorder captures the response status code.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
	bytes      int64
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Run starts the proxy and blocks until the context is cancelled.
func (p *Proxy) Run(ctx context.Context) error {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: p.opts.Timeout,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.opts.SkipVerify,
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = p.backend.Scheme
			req.URL.Host = p.backend.Host
			if p.backend.Path != "" && p.backend.Path != "/" {
				req.URL.Path = singleJoiningSlash(p.backend.Path, req.URL.Path)
			}
			req.Host = p.backend.Host

			// Apply header rules
			for _, h := range p.opts.Headers {
				if h.Remove {
					req.Header.Del(h.Name)
				} else {
					req.Header.Set(h.Name, h.Value)
				}
			}

			// Add standard proxy headers
			if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
					clientIP = prior + ", " + clientIP
				}
				req.Header.Set("X-Forwarded-For", clientIP)
			}
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "Proxy error: %v", err)
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, statusCode: 200}

		rp.ServeHTTP(rec, r)

		latency := time.Since(start)
		log := RequestLog{
			Timestamp:  start,
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: rec.statusCode,
			Latency:    latency,
			ClientAddr: r.RemoteAddr,
			BytesSent:  rec.bytes,
		}

		p.Stats.Record(log)

		if p.opts.OnRequest != nil {
			p.opts.OnRequest(log)
		}
	})

	p.server = &http.Server{
		Addr:         p.opts.ListenAddr,
		Handler:      handler,
		ReadTimeout:  p.opts.Timeout,
		WriteTimeout: p.opts.Timeout,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
