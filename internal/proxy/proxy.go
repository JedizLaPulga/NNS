// Package proxy provides HTTP proxy server functionality.
// Package proxy implements a simple HTTP/HTTPS debug proxy.
package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Config holds proxy configuration.
type Config struct {
	Port    int
	Verbose bool
	Filter  string
}

// Proxy is a debug proxy server.
type Proxy struct {
	cfg       Config
	server    *http.Server
	requestID uint64
	client    *http.Client
}

// NewProxy creates a new Proxy instance.
func NewProxy(cfg Config) *Proxy {
	return &Proxy{
		cfg: cfg,
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects, just forward them
			},
			Timeout: 30 * time.Second,
		},
	}
}

// Start starts the proxy server.
func (p *Proxy) Start() error {
	addr := fmt.Sprintf(":%d", p.cfg.Port)
	p.server = &http.Server{
		Addr:    addr,
		Handler: p,
	}

	log.Printf("[INFO] Proxy listening on %s", addr)
	return p.server.ListenAndServe()
}

// ServeHTTP handles incoming requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS tunneling via CONNECT method.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := atomic.AddUint64(&p.requestID, 1)

	if p.shouldLog(r.Host) {
		log.Printf("[%d] --> CONNECT %s", id, r.Host)
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("[%d] Dial failed: %v", id, err)
		return
	}
	defer targetConn.Close()

	// Send 200 OK to client to establish tunnel
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)

	if p.shouldLog(r.Host) {
		log.Printf("[%d] <-- Tunnel Closed (%v)", id, time.Since(start))
	}
}

// handleHTTP handles standard HTTP forwarding.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := atomic.AddUint64(&p.requestID, 1)

	if p.shouldLog(r.URL.String()) {
		log.Printf("[%d] --> %s %s", id, r.Method, r.URL)
	}

	// Create request
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Perform request
	resp, err := p.client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		if p.shouldLog(r.URL.String()) {
			log.Printf("[%d] <-- Error: %v", id, err)
		}
		return
	}
	defer resp.Body.Close()

	// Copy headers back
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy body back
	n, _ := io.Copy(w, resp.Body)

	if p.shouldLog(r.URL.String()) {
		log.Printf("[%d] <-- %s (%v) - %s", id, resp.Status, time.Since(start), formatBytes(n))
	}
}

func (p *Proxy) shouldLog(target string) bool {
	if p.cfg.Filter == "" {
		return true
	}
	return strings.Contains(target, p.cfg.Filter)
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n >= div && div > unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f KB", float64(n)/float64(unit))
}

// TODO: Implement HTTP proxy server functionality
// This will use net/http for the proxy server implementation
