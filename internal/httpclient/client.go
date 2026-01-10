// Package httpclient provides an HTTP client with detailed timing breakdown.
package httpclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

// Timing holds timing information for the HTTP request.
type Timing struct {
	DNSStart     time.Time     `json:"-"`
	DNSDone      time.Time     `json:"-"`
	ConnectStart time.Time     `json:"-"`
	ConnectDone  time.Time     `json:"-"`
	TLSStart     time.Time     `json:"-"`
	TLSDone      time.Time     `json:"-"`
	FirstByte    time.Time     `json:"-"`
	Done         time.Time     `json:"-"`
	Start        time.Time     `json:"-"`
	DNSLookup    time.Duration `json:"dns_lookup"`
	TCPConnect   time.Duration `json:"tcp_connect"`
	TLSHandshake time.Duration `json:"tls_handshake"`
	TTFB         time.Duration `json:"ttfb"`
	Download     time.Duration `json:"download"`
	Total        time.Duration `json:"total"`
}

// Request represents an HTTP request configuration.
type Request struct {
	Method       string
	URL          string
	Headers      map[string]string
	Body         string
	Timeout      time.Duration
	FollowRedirs bool
}

// Response holds the HTTP response and timing data.
type Response struct {
	StatusCode    int               `json:"status_code"`
	Status        string            `json:"status"`
	Proto         string            `json:"protocol"`
	Headers       map[string]string `json:"headers"`
	Body          []byte            `json:"-"`
	BodyString    string            `json:"body,omitempty"`
	ContentLength int64             `json:"content_length"`
	ContentType   string            `json:"content_type"`
	Timing        Timing            `json:"timing"`
	RedirectCount int               `json:"redirect_count"`
	FinalURL      string            `json:"final_url"`
}

// Client is the HTTP client with timing support.
type Client struct {
	Timeout         time.Duration
	FollowRedirects bool
	MaxBodySize     int64
}

// NewClient creates a new HTTP client with defaults.
func NewClient() *Client {
	return &Client{
		Timeout:         30 * time.Second,
		FollowRedirects: true,
		MaxBodySize:     1024 * 1024, // 1MB default
	}
}

// Do performs an HTTP request with timing.
func (c *Client) Do(req *Request) (*Response, error) {
	resp := &Response{}
	timing := &Timing{}

	// Build HTTP request
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	httpReq, err := http.NewRequest(method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Set headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Default User-Agent
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", "nns-http/1.0")
	}

	// Content-Type for body
	if req.Body != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Setup trace for timing
	timing.Start = time.Now()

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			timing.DNSStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			timing.DNSDone = time.Now()
		},
		ConnectStart: func(network, addr string) {
			timing.ConnectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			timing.ConnectDone = time.Now()
		},
		TLSHandshakeStart: func() {
			timing.TLSStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			timing.TLSDone = time.Now()
		},
		GotFirstResponseByte: func() {
			timing.FirstByte = time.Now()
		},
	}

	ctx := httptrace.WithClientTrace(context.Background(), trace)
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	} else if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	httpReq = httpReq.WithContext(ctx)

	// Create client
	transport := &http.Transport{
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   c.Timeout,
	}

	if !c.FollowRedirects && !req.FollowRedirs {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Execute request
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	timing.Done = time.Now()

	// Read body
	maxSize := c.MaxBodySize
	if maxSize <= 0 {
		maxSize = 1024 * 1024
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Calculate timings
	if !timing.DNSStart.IsZero() && !timing.DNSDone.IsZero() {
		timing.DNSLookup = timing.DNSDone.Sub(timing.DNSStart)
	}
	if !timing.ConnectStart.IsZero() && !timing.ConnectDone.IsZero() {
		timing.TCPConnect = timing.ConnectDone.Sub(timing.ConnectStart)
	}
	if !timing.TLSStart.IsZero() && !timing.TLSDone.IsZero() {
		timing.TLSHandshake = timing.TLSDone.Sub(timing.TLSStart)
	}
	if !timing.FirstByte.IsZero() {
		timing.TTFB = timing.FirstByte.Sub(timing.Start)
	}
	if !timing.FirstByte.IsZero() && !timing.Done.IsZero() {
		timing.Download = timing.Done.Sub(timing.FirstByte)
	}
	timing.Total = timing.Done.Sub(timing.Start)

	// Build response
	resp.StatusCode = httpResp.StatusCode
	resp.Status = httpResp.Status
	resp.Proto = httpResp.Proto
	resp.ContentLength = httpResp.ContentLength
	resp.ContentType = httpResp.Header.Get("Content-Type")
	resp.Body = body
	resp.Timing = *timing
	resp.FinalURL = httpResp.Request.URL.String()

	// Copy headers
	resp.Headers = make(map[string]string)
	for k, v := range httpResp.Header {
		if len(v) > 0 {
			resp.Headers[k] = v[0]
		}
	}

	return resp, nil
}

// ToJSON converts response to JSON.
func (r *Response) ToJSON() (string, error) {
	r.BodyString = string(r.Body)
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// IsSuccess returns true if status code is 2xx.
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsRedirect returns true if status code is 3xx.
func (r *Response) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

// ParseURL validates and normalizes a URL.
func ParseURL(input string) string {
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		return "https://" + input
	}
	return input
}

// FormatSize formats bytes to human readable.
func FormatSize(bytes int64) string {
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

// LookupIP resolves hostname to IP for display.
func LookupIP(host string) string {
	// Extract host from URL
	if strings.Contains(host, "://") {
		parts := strings.SplitN(host, "://", 2)
		if len(parts) == 2 {
			host = parts[1]
		}
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}
