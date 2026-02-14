// Package httptrace provides HTTP request tracing with redirect chain following,
// timing breakdown per hop, and header inspection.
package httptrace

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

// TraceOptions configures an HTTP trace operation.
type TraceOptions struct {
	URL            string
	Method         string
	MaxRedirects   int
	Timeout        time.Duration
	FollowRedirect bool
	InsecureSkip   bool
	Headers        map[string]string
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() TraceOptions {
	return TraceOptions{
		Method:         "GET",
		MaxRedirects:   10,
		Timeout:        30 * time.Second,
		FollowRedirect: true,
	}
}

// HopTiming holds timing information for a single HTTP hop.
type HopTiming struct {
	DNSStart    time.Time     `json:"-"`
	DNSDone     time.Time     `json:"-"`
	DNSDuration time.Duration `json:"dns_duration"`

	ConnectStart    time.Time     `json:"-"`
	ConnectDone     time.Time     `json:"-"`
	ConnectDuration time.Duration `json:"connect_duration"`

	TLSStart    time.Time     `json:"-"`
	TLSDone     time.Time     `json:"-"`
	TLSDuration time.Duration `json:"tls_duration"`

	FirstByteTime time.Duration `json:"first_byte_time"`
	TotalTime     time.Duration `json:"total_time"`
}

// Hop represents a single step in the HTTP redirect chain.
type Hop struct {
	Number          int               `json:"number"`
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	StatusCode      int               `json:"status_code"`
	Status          string            `json:"status"`
	Proto           string            `json:"protocol"`
	ContentLength   int64             `json:"content_length"`
	ContentType     string            `json:"content_type"`
	Location        string            `json:"location,omitempty"`
	ServerIP        string            `json:"server_ip,omitempty"`
	TLSVersion      string            `json:"tls_version,omitempty"`
	TLSCipher       string            `json:"tls_cipher,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	Timing          HopTiming         `json:"timing"`
	Error           string            `json:"error,omitempty"`
}

// TraceResult holds the complete trace of an HTTP request.
type TraceResult struct {
	Hops           []Hop         `json:"hops"`
	FinalURL       string        `json:"final_url"`
	FinalStatus    int           `json:"final_status"`
	TotalTime      time.Duration `json:"total_time"`
	TotalRedirects int           `json:"total_redirects"`
	Error          string        `json:"error,omitempty"`
}

// Trace performs an HTTP request trace, following redirects and recording timing.
func Trace(ctx context.Context, opts TraceOptions) (*TraceResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}
	if opts.Method == "" {
		opts.Method = "GET"
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	result := &TraceResult{}
	start := time.Now()

	currentURL := opts.URL
	method := opts.Method

	for i := 0; i <= opts.MaxRedirects; i++ {
		hop, err := traceHop(ctx, currentURL, method, i+1, opts)
		if err != nil {
			hop.Error = err.Error()
			result.Hops = append(result.Hops, hop)
			result.Error = err.Error()
			break
		}

		result.Hops = append(result.Hops, hop)

		if !isRedirect(hop.StatusCode) || !opts.FollowRedirect {
			break
		}

		if hop.Location == "" {
			break
		}

		currentURL = hop.Location
		// 301, 302, 303 use GET after redirect; 307, 308 preserve method
		if hop.StatusCode == 303 || (hop.StatusCode != 307 && hop.StatusCode != 308) {
			method = "GET"
		}
	}

	result.TotalTime = time.Since(start)
	if len(result.Hops) > 0 {
		last := result.Hops[len(result.Hops)-1]
		result.FinalURL = last.URL
		result.FinalStatus = last.StatusCode
		result.TotalRedirects = len(result.Hops) - 1
		if result.TotalRedirects < 0 {
			result.TotalRedirects = 0
		}
	}

	return result, nil
}

func traceHop(ctx context.Context, rawURL, method string, hopNum int, opts TraceOptions) (Hop, error) {
	hop := Hop{
		Number:          hopNum,
		URL:             rawURL,
		Method:          method,
		RequestHeaders:  make(map[string]string),
		ResponseHeaders: make(map[string]string),
	}

	var timing HopTiming

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			timing.DNSStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			timing.DNSDone = time.Now()
			timing.DNSDuration = timing.DNSDone.Sub(timing.DNSStart)
			if len(info.Addrs) > 0 {
				hop.ServerIP = info.Addrs[0].String()
			}
		},
		ConnectStart: func(_, _ string) {
			timing.ConnectStart = time.Now()
		},
		ConnectDone: func(_, addr string, err error) {
			timing.ConnectDone = time.Now()
			timing.ConnectDuration = timing.ConnectDone.Sub(timing.ConnectStart)
			if hop.ServerIP == "" {
				host, _, _ := net.SplitHostPort(addr)
				hop.ServerIP = host
			}
		},
		TLSHandshakeStart: func() {
			timing.TLSStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			timing.TLSDone = time.Now()
			timing.TLSDuration = timing.TLSDone.Sub(timing.TLSStart)
			hop.TLSVersion = tlsVersionName(state.Version)
			hop.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
		},
		GotFirstResponseByte: func() {
			timing.FirstByteTime = time.Since(timing.DNSStart)
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, rawURL, nil)
	if err != nil {
		return hop, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "nns/httptrace")
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
		hop.RequestHeaders[k] = v
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.InsecureSkip,
			},
		},
	}

	hopStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return hop, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	timing.TotalTime = time.Since(hopStart)
	hop.Timing = timing

	hop.StatusCode = resp.StatusCode
	hop.Status = resp.Status
	hop.Proto = resp.Proto
	hop.ContentLength = resp.ContentLength
	hop.ContentType = resp.Header.Get("Content-Type")
	hop.Location = resp.Header.Get("Location")

	for k, v := range resp.Header {
		hop.ResponseHeaders[k] = strings.Join(v, "; ")
	}

	return hop, nil
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

// FormatResult returns a human-readable string for the trace result.
func FormatResult(r *TraceResult) string {
	var sb strings.Builder

	for _, hop := range r.Hops {
		sb.WriteString(fmt.Sprintf("── Hop %d ──\n", hop.Number))
		sb.WriteString(fmt.Sprintf("  URL:          %s\n", hop.URL))
		sb.WriteString(fmt.Sprintf("  Method:       %s\n", hop.Method))

		if hop.Error != "" {
			sb.WriteString(fmt.Sprintf("  Error:        %s\n", hop.Error))
			continue
		}

		sb.WriteString(fmt.Sprintf("  Status:       %s\n", hop.Status))
		sb.WriteString(fmt.Sprintf("  Protocol:     %s\n", hop.Proto))

		if hop.ServerIP != "" {
			sb.WriteString(fmt.Sprintf("  Server IP:    %s\n", hop.ServerIP))
		}
		if hop.ContentType != "" {
			sb.WriteString(fmt.Sprintf("  Content-Type: %s\n", hop.ContentType))
		}
		if hop.ContentLength >= 0 {
			sb.WriteString(fmt.Sprintf("  Content-Len:  %d bytes\n", hop.ContentLength))
		}

		if hop.TLSVersion != "" {
			sb.WriteString(fmt.Sprintf("  TLS:          %s (%s)\n", hop.TLSVersion, hop.TLSCipher))
		}

		if hop.Location != "" {
			sb.WriteString(fmt.Sprintf("  Redirect:     %s\n", hop.Location))
		}

		// Timing
		sb.WriteString("  Timing:\n")
		if hop.Timing.DNSDuration > 0 {
			sb.WriteString(fmt.Sprintf("    DNS:        %v\n", hop.Timing.DNSDuration.Round(time.Millisecond)))
		}
		if hop.Timing.ConnectDuration > 0 {
			sb.WriteString(fmt.Sprintf("    Connect:    %v\n", hop.Timing.ConnectDuration.Round(time.Millisecond)))
		}
		if hop.Timing.TLSDuration > 0 {
			sb.WriteString(fmt.Sprintf("    TLS:        %v\n", hop.Timing.TLSDuration.Round(time.Millisecond)))
		}
		if hop.Timing.FirstByteTime > 0 {
			sb.WriteString(fmt.Sprintf("    TTFB:       %v\n", hop.Timing.FirstByteTime.Round(time.Millisecond)))
		}
		sb.WriteString(fmt.Sprintf("    Total:      %v\n", hop.Timing.TotalTime.Round(time.Millisecond)))

		// Security headers
		secHeaders := []string{
			"Strict-Transport-Security",
			"Content-Security-Policy",
			"X-Frame-Options",
			"X-Content-Type-Options",
			"Referrer-Policy",
			"Permissions-Policy",
		}
		headerFound := false
		for _, h := range secHeaders {
			if v, ok := hop.ResponseHeaders[h]; ok {
				if !headerFound {
					sb.WriteString("  Security Headers:\n")
					headerFound = true
				}
				display := v
				if len(display) > 60 {
					display = display[:60] + "..."
				}
				sb.WriteString(fmt.Sprintf("    %-30s %s\n", h+":", display))
			}
		}

		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString("── Summary ──\n")
	sb.WriteString(fmt.Sprintf("  Final URL:    %s\n", r.FinalURL))
	sb.WriteString(fmt.Sprintf("  Final Status: %d\n", r.FinalStatus))
	sb.WriteString(fmt.Sprintf("  Redirects:    %d\n", r.TotalRedirects))
	sb.WriteString(fmt.Sprintf("  Total Time:   %v\n", r.TotalTime.Round(time.Millisecond)))

	if r.Error != "" {
		sb.WriteString(fmt.Sprintf("  Error:        %s\n", r.Error))
	}

	return sb.String()
}
