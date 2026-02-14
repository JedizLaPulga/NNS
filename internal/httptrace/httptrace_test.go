package httptrace

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Method != "GET" {
		t.Errorf("expected default method GET, got %s", opts.Method)
	}
	if opts.MaxRedirects != 10 {
		t.Errorf("expected 10 max redirects, got %d", opts.MaxRedirects)
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", opts.Timeout)
	}
	if !opts.FollowRedirect {
		t.Error("expected FollowRedirect=true")
	}
}

func TestTraceSimple(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.URL = srv.URL

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	if len(result.Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(result.Hops))
	}
	if result.FinalStatus != 200 {
		t.Errorf("expected status 200, got %d", result.FinalStatus)
	}
	if result.TotalRedirects != 0 {
		t.Errorf("expected 0 redirects, got %d", result.TotalRedirects)
	}
}

func TestTraceRedirect(t *testing.T) {
	finalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Final")
	}))
	defer finalSrv.Close()

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalSrv.URL, http.StatusMovedPermanently)
	}))
	defer redirectSrv.Close()

	opts := DefaultOptions()
	opts.URL = redirectSrv.URL

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	if len(result.Hops) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(result.Hops))
	}
	if result.Hops[0].StatusCode != 301 {
		t.Errorf("expected first hop status 301, got %d", result.Hops[0].StatusCode)
	}
	if result.FinalStatus != 200 {
		t.Errorf("expected final status 200, got %d", result.FinalStatus)
	}
	if result.TotalRedirects != 1 {
		t.Errorf("expected 1 redirect, got %d", result.TotalRedirects)
	}
}

func TestTraceNoFollowRedirect(t *testing.T) {
	finalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer finalSrv.Close()

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalSrv.URL, http.StatusFound)
	}))
	defer redirectSrv.Close()

	opts := DefaultOptions()
	opts.URL = redirectSrv.URL
	opts.FollowRedirect = false

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	if len(result.Hops) != 1 {
		t.Fatalf("expected 1 hop (no follow), got %d", len(result.Hops))
	}
	if result.FinalStatus != 302 {
		t.Errorf("expected status 302, got %d", result.FinalStatus)
	}
}

func TestTraceMultipleRedirects(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/middle", http.StatusFound)
	})
	mux.HandleFunc("/middle", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/end", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "Done")
	})

	opts := DefaultOptions()
	opts.URL = srv.URL + "/start"

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	if len(result.Hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(result.Hops))
	}
	if result.TotalRedirects != 2 {
		t.Errorf("expected 2 redirects, got %d", result.TotalRedirects)
	}
}

func TestTraceCustomHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "test-value" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.URL = srv.URL
	opts.Headers = map[string]string{
		"X-Custom": "test-value",
	}

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	if result.FinalStatus != 200 {
		t.Errorf("expected 200 with custom header, got %d", result.FinalStatus)
	}
}

func TestTraceResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "hello")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.URL = srv.URL

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	hop := result.Hops[0]
	if hop.ResponseHeaders["X-Test-Header"] != "hello" {
		t.Error("expected X-Test-Header in response headers")
	}
	if hop.ContentType != "application/json" {
		t.Errorf("expected application/json content type, got %s", hop.ContentType)
	}
}

func TestTraceTimings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.URL = srv.URL

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	hop := result.Hops[0]
	if hop.Timing.TotalTime <= 0 {
		t.Error("expected positive total time")
	}
	if result.TotalTime <= 0 {
		t.Error("expected positive total result time")
	}
}

func TestTraceCancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := DefaultOptions()
	opts.URL = srv.URL
	opts.Timeout = 1 * time.Second

	result, _ := Trace(ctx, opts)
	if result.Error == "" {
		t.Error("expected error for cancelled context")
	}
}

func TestTraceSecurityHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.URL = srv.URL

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	hop := result.Hops[0]
	if hop.ResponseHeaders["Strict-Transport-Security"] != "max-age=31536000" {
		t.Error("expected HSTS header")
	}
	if hop.ResponseHeaders["X-Frame-Options"] != "DENY" {
		t.Error("expected X-Frame-Options header")
	}
}

func TestFormatResultOutput(t *testing.T) {
	result := &TraceResult{
		Hops: []Hop{
			{
				Number:     1,
				URL:        "http://example.com",
				Method:     "GET",
				StatusCode: 301,
				Status:     "301 Moved Permanently",
				Proto:      "HTTP/1.1",
				Location:   "https://example.com",
				Timing:     HopTiming{TotalTime: 100 * time.Millisecond},
				ResponseHeaders: map[string]string{
					"Location": "https://example.com",
				},
			},
			{
				Number:     2,
				URL:        "https://example.com",
				Method:     "GET",
				StatusCode: 200,
				Status:     "200 OK",
				Proto:      "HTTP/2.0",
				TLSVersion: "TLS 1.3",
				TLSCipher:  "TLS_AES_128_GCM_SHA256",
				Timing:     HopTiming{TotalTime: 200 * time.Millisecond},
				ResponseHeaders: map[string]string{
					"Strict-Transport-Security": "max-age=31536000",
				},
			},
		},
		FinalURL:       "https://example.com",
		FinalStatus:    200,
		TotalRedirects: 1,
		TotalTime:      300 * time.Millisecond,
	}

	output := FormatResult(result)

	checks := []string{
		"Hop 1",
		"Hop 2",
		"301",
		"200",
		"example.com",
		"Summary",
		"Redirects",
		"TLS 1.3",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("format output should contain %q", check)
		}
	}
}

func TestFormatResultWithError(t *testing.T) {
	result := &TraceResult{
		Hops: []Hop{
			{
				Number:          1,
				URL:             "http://nonexistent.invalid",
				Method:          "GET",
				Error:           "connection refused",
				ResponseHeaders: map[string]string{},
			},
		},
		Error:     "connection refused",
		TotalTime: 50 * time.Millisecond,
	}

	output := FormatResult(result)
	if !strings.Contains(output, "connection refused") {
		t.Error("format should include error message")
	}
}

func TestIsRedirect(t *testing.T) {
	redirectCodes := []int{301, 302, 303, 307, 308}
	for _, code := range redirectCodes {
		if !isRedirect(code) {
			t.Errorf("expected %d to be redirect", code)
		}
	}

	nonRedirectCodes := []int{200, 404, 500, 100, 204}
	for _, code := range nonRedirectCodes {
		if isRedirect(code) {
			t.Errorf("expected %d to NOT be redirect", code)
		}
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0000, "0x0000"},
	}
	for _, tt := range tests {
		got := tlsVersionName(tt.version)
		if got != tt.want {
			t.Errorf("tlsVersionName(0x%04X) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestTraceHopFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.URL = srv.URL

	result, err := Trace(context.Background(), opts)
	if err != nil {
		t.Fatalf("trace failed: %v", err)
	}

	hop := result.Hops[0]
	if hop.Number != 1 {
		t.Errorf("expected hop number 1, got %d", hop.Number)
	}
	if hop.Method != "GET" {
		t.Errorf("expected GET method, got %s", hop.Method)
	}
	if hop.Proto == "" {
		t.Error("expected non-empty protocol")
	}
}
