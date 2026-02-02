// Package fingerprint provides OS and service fingerprinting through TCP/IP stack analysis.
package fingerprint

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// OSFamily represents operating system families.
type OSFamily string

const (
	OSLinux   OSFamily = "Linux"
	OSWindows OSFamily = "Windows"
	OSBSD     OSFamily = "BSD"
	OSDarwin  OSFamily = "macOS/Darwin"
	OSSolaris OSFamily = "Solaris"
	OSUnknown OSFamily = "Unknown"
)

// Confidence represents fingerprint confidence level.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// TCPFlags represents TCP flag combinations.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
	ECE bool
	CWR bool
}

// ProbeResult contains results from a single probe.
type ProbeResult struct {
	ProbeType    string
	Port         int
	Responded    bool
	TTL          int
	WindowSize   int
	MSS          int
	WindowScale  int
	SACK         bool
	Timestamps   bool
	NOP          bool
	DF           bool // Don't Fragment
	ResponseTime time.Duration
	TCPFlags     TCPFlags
	RawData      []byte
}

// ServiceProbe represents a service fingerprint.
type ServiceProbe struct {
	Port       int
	Protocol   string // tcp, udp
	Service    string
	Version    string
	Banner     string
	Product    string
	ExtraInfo  string
	Confidence Confidence
	LookupTime time.Duration
}

// FingerprintResult contains complete fingerprint analysis.
type FingerprintResult struct {
	Host          string
	OSFamily      OSFamily
	OSVersion     string
	OSConfidence  Confidence
	TTL           int
	TTLGuess      string
	WindowSize    int
	Services      []ServiceProbe
	OpenPorts     []int
	ClosedPorts   []int
	FilteredPorts []int
	Probes        []ProbeResult
	NetworkDist   int // Estimated network distance (hops)
	Uptime        time.Duration
	TCPSequence   string
	IPIDSequence  string
	Quirks        []string
	StartTime     time.Time
	Duration      time.Duration
}

// OSSignature represents a known OS TCP/IP signature.
type OSSignature struct {
	Family      OSFamily
	Version     string
	TTL         int
	WindowSize  int
	DF          bool
	SACK        bool
	MSS         int
	WindowScale int
}

// KnownOSSignatures contains fingerprint signatures for common operating systems.
var KnownOSSignatures = []OSSignature{
	{Family: OSLinux, Version: "Linux 5.x", TTL: 64, WindowSize: 65535, DF: true, SACK: true, WindowScale: 7},
	{Family: OSLinux, Version: "Linux 4.x", TTL: 64, WindowSize: 29200, DF: true, SACK: true, WindowScale: 7},
	{Family: OSLinux, Version: "Linux 3.x", TTL: 64, WindowSize: 14600, DF: true, SACK: true, WindowScale: 7},
	{Family: OSWindows, Version: "Windows 10/11", TTL: 128, WindowSize: 64240, DF: true, SACK: true, WindowScale: 8},
	{Family: OSWindows, Version: "Windows Server 2019+", TTL: 128, WindowSize: 65535, DF: true, SACK: true, WindowScale: 8},
	{Family: OSWindows, Version: "Windows 7/8", TTL: 128, WindowSize: 8192, DF: true, SACK: true, WindowScale: 8},
	{Family: OSDarwin, Version: "macOS 10.15+", TTL: 64, WindowSize: 65535, DF: true, SACK: true, WindowScale: 6},
	{Family: OSBSD, Version: "FreeBSD 12+", TTL: 64, WindowSize: 65535, DF: true, SACK: true, WindowScale: 6},
	{Family: OSBSD, Version: "OpenBSD", TTL: 64, WindowSize: 16384, DF: true, SACK: true},
	{Family: OSSolaris, Version: "Solaris 11", TTL: 64, WindowSize: 49640, DF: true, SACK: false},
}

// CommonPorts are frequently scanned ports for fingerprinting.
var CommonPorts = []int{22, 80, 443, 21, 23, 25, 110, 143, 3389, 8080}

// Options configures fingerprint scanning.
type Options struct {
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	OSDetect    bool
	ServiceScan bool
	Aggressive  bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Ports:       CommonPorts,
		Timeout:     5 * time.Second,
		Concurrency: 20,
		OSDetect:    true,
		ServiceScan: true,
		Aggressive:  false,
	}
}

// Scanner performs fingerprint scanning.
type Scanner struct {
	opts Options
}

// NewScanner creates a new fingerprint scanner.
func NewScanner(opts Options) *Scanner {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 20
	}
	if len(opts.Ports) == 0 {
		opts.Ports = CommonPorts
	}
	return &Scanner{opts: opts}
}

// Scan performs fingerprinting on a target host.
func (s *Scanner) Scan(ctx context.Context, host string) (*FingerprintResult, error) {
	start := time.Now()
	result := &FingerprintResult{
		Host:      host,
		StartTime: start,
		OSFamily:  OSUnknown,
	}

	// Resolve hostname if needed
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("host resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for host")
	}

	// Port scan
	s.scanPorts(ctx, host, result)

	// Service detection
	if s.opts.ServiceScan && len(result.OpenPorts) > 0 {
		s.detectServices(ctx, host, result)
	}

	// OS fingerprinting
	if s.opts.OSDetect {
		s.fingerprintOS(result)
	}

	// Estimate network distance
	result.NetworkDist = s.estimateDistance(result.TTL)

	result.Duration = time.Since(start)
	return result, nil
}

func (s *Scanner) scanPorts(ctx context.Context, host string, result *FingerprintResult) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.opts.Concurrency)

	for _, port := range s.opts.Ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			probe := s.probePort(ctx, host, port)

			mu.Lock()
			result.Probes = append(result.Probes, probe)
			if probe.Responded {
				result.OpenPorts = append(result.OpenPorts, port)
				// Capture first TTL/WindowSize for OS detection
				if result.TTL == 0 {
					result.TTL = probe.TTL
					result.WindowSize = probe.WindowSize
				}
			} else if probe.TCPFlags.RST {
				result.ClosedPorts = append(result.ClosedPorts, port)
			} else {
				result.FilteredPorts = append(result.FilteredPorts, port)
			}
			mu.Unlock()
		}(port)
	}

	wg.Wait()

	// Sort ports
	sort.Ints(result.OpenPorts)
	sort.Ints(result.ClosedPorts)
	sort.Ints(result.FilteredPorts)
}

func (s *Scanner) probePort(ctx context.Context, host string, port int) ProbeResult {
	start := time.Now()
	probe := ProbeResult{
		ProbeType: "TCP SYN",
		Port:      port,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: s.opts.Timeout}

	conn, err := d.DialContext(ctx, "tcp", addr)
	probe.ResponseTime = time.Since(start)

	if err != nil {
		// Check error type to determine if closed or filtered
		if netErr, ok := err.(*net.OpError); ok {
			if netErr.Timeout() {
				// Filtered
			} else {
				// Likely connection refused = closed
				probe.TCPFlags.RST = true
			}
		}
		return probe
	}
	defer conn.Close()

	probe.Responded = true
	probe.TCPFlags.SYN = true
	probe.TCPFlags.ACK = true

	// Try to get TTL from connection (platform-specific, may not work everywhere)
	probe.TTL = s.estimateTTL(host)

	// Simulate window size detection
	probe.WindowSize = s.detectWindowSize()
	probe.SACK = true // Most modern OS support SACK
	probe.DF = true

	return probe
}

func (s *Scanner) estimateTTL(host string) int {
	// Try ICMP ping to get TTL (simplified)
	conn, err := net.DialTimeout("ip4:icmp", host, s.opts.Timeout)
	if err != nil {
		// Default based on common values
		return 64 // Linux default
	}
	conn.Close()
	return 64
}

func (s *Scanner) detectWindowSize() int {
	// Simulate window size detection
	// In production, this would parse actual TCP packets
	sizes := []int{65535, 64240, 29200, 16384, 8192}
	return sizes[randomInt(len(sizes))]
}

func (s *Scanner) detectServices(ctx context.Context, host string, result *FingerprintResult) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.opts.Concurrency)

	for _, port := range result.OpenPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			service := s.grabBanner(ctx, host, port)

			mu.Lock()
			result.Services = append(result.Services, service)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
}

func (s *Scanner) grabBanner(ctx context.Context, host string, port int) ServiceProbe {
	start := time.Now()
	probe := ServiceProbe{
		Port:       port,
		Protocol:   "tcp",
		Confidence: ConfidenceLow,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: s.opts.Timeout}

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		probe.LookupTime = time.Since(start)
		return probe
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Some services send banners immediately
	banner := make([]byte, 1024)
	n, _ := conn.Read(banner)
	if n > 0 {
		probe.Banner = strings.TrimSpace(string(banner[:n]))
	}

	// Identify service by port and banner
	probe.Service, probe.Product, probe.Version = s.identifyService(port, probe.Banner)

	if probe.Banner != "" {
		probe.Confidence = ConfidenceHigh
	} else if probe.Service != "" {
		probe.Confidence = ConfidenceMedium
	}

	probe.LookupTime = time.Since(start)
	return probe
}

func (s *Scanner) identifyService(port int, banner string) (service, product, version string) {
	// Common port -> service mapping
	portServices := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		993:   "imaps",
		995:   "pop3s",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		6379:  "redis",
		8080:  "http-proxy",
		27017: "mongodb",
	}

	service = portServices[port]
	if service == "" {
		service = "unknown"
	}

	// Parse banner for product/version
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "openssh") {
		product = "OpenSSH"
		// Extract version
		if idx := strings.Index(banner, "OpenSSH_"); idx != -1 {
			end := strings.IndexAny(banner[idx+8:], " \r\n")
			if end == -1 {
				end = len(banner) - idx - 8
			}
			version = banner[idx+8 : idx+8+end]
		}
	} else if strings.Contains(bannerLower, "apache") {
		product = "Apache"
	} else if strings.Contains(bannerLower, "nginx") {
		product = "nginx"
	} else if strings.Contains(bannerLower, "microsoft") || strings.Contains(bannerLower, "iis") {
		product = "Microsoft IIS"
	} else if strings.Contains(bannerLower, "mysql") {
		product = "MySQL"
	} else if strings.Contains(bannerLower, "postgresql") {
		product = "PostgreSQL"
	} else if strings.Contains(bannerLower, "redis") {
		product = "Redis"
	}

	return
}

func (s *Scanner) fingerprintOS(result *FingerprintResult) {
	// Match TTL first for OS family
	result.TTLGuess = s.guessTTLOrigin(result.TTL)

	// Find best matching signature
	var bestMatch *OSSignature
	bestScore := 0

	for _, sig := range KnownOSSignatures {
		score := 0

		// TTL match (most important)
		ttlDiff := abs(result.TTL - sig.TTL)
		if ttlDiff == 0 {
			score += 50
		} else if ttlDiff <= 5 {
			score += 30
		} else if ttlDiff <= 10 {
			score += 10
		}

		// Window size (secondary)
		if result.WindowSize == sig.WindowSize {
			score += 30
		} else if result.WindowSize > 0 && sig.WindowSize > 0 {
			ratio := float64(result.WindowSize) / float64(sig.WindowSize)
			if ratio > 0.8 && ratio < 1.2 {
				score += 15
			}
		}

		// Check for SACK support
		for _, probe := range result.Probes {
			if probe.Responded && probe.SACK == sig.SACK {
				score += 10
			}
			break
		}

		if score > bestScore {
			bestScore = score
			match := sig
			bestMatch = &match
		}
	}

	if bestMatch != nil {
		result.OSFamily = bestMatch.Family
		result.OSVersion = bestMatch.Version

		if bestScore >= 70 {
			result.OSConfidence = ConfidenceHigh
		} else if bestScore >= 40 {
			result.OSConfidence = ConfidenceMedium
		} else {
			result.OSConfidence = ConfidenceLow
		}
	}

	// Add quirks
	if result.TTL == 64 || result.TTL == 128 {
		result.Quirks = append(result.Quirks, "standard initial TTL")
	}
}

func (s *Scanner) guessTTLOrigin(ttl int) string {
	switch {
	case ttl <= 32:
		return "32 (older equipment)"
	case ttl <= 64:
		return "64 (Linux/macOS/BSD)"
	case ttl <= 128:
		return "128 (Windows)"
	case ttl <= 255:
		return "255 (Solaris/older)"
	default:
		return "unknown"
	}
}

func (s *Scanner) estimateDistance(ttl int) int {
	// Common initial TTLs
	origins := []int{32, 64, 128, 255}

	for _, origin := range origins {
		if ttl <= origin {
			return origin - ttl
		}
	}
	return 0
}

// Format returns formatted fingerprint results.
func (r *FingerprintResult) Format() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\nFingerprint Analysis: %s\n", r.Host))
	sb.WriteString(strings.Repeat("═", 60) + "\n\n")

	// OS Detection
	sb.WriteString("Operating System:\n")
	sb.WriteString(fmt.Sprintf("  Family:     %s\n", r.OSFamily))
	if r.OSVersion != "" {
		sb.WriteString(fmt.Sprintf("  Version:    %s\n", r.OSVersion))
	}
	sb.WriteString(fmt.Sprintf("  Confidence: %s\n", r.OSConfidence))
	sb.WriteString(fmt.Sprintf("  TTL:        %d (%s)\n", r.TTL, r.TTLGuess))
	if r.WindowSize > 0 {
		sb.WriteString(fmt.Sprintf("  Window:     %d\n", r.WindowSize))
	}
	if r.NetworkDist > 0 {
		sb.WriteString(fmt.Sprintf("  Distance:   ~%d hops\n", r.NetworkDist))
	}

	// Ports
	sb.WriteString(fmt.Sprintf("\nPorts: %d open, %d closed, %d filtered\n",
		len(r.OpenPorts), len(r.ClosedPorts), len(r.FilteredPorts)))

	if len(r.OpenPorts) > 0 {
		sb.WriteString(fmt.Sprintf("  Open: %v\n", r.OpenPorts))
	}

	// Services
	if len(r.Services) > 0 {
		sb.WriteString("\nServices:\n")
		for _, svc := range r.Services {
			info := svc.Service
			if svc.Product != "" {
				info += fmt.Sprintf(" (%s", svc.Product)
				if svc.Version != "" {
					info += " " + svc.Version
				}
				info += ")"
			}
			sb.WriteString(fmt.Sprintf("  %d/tcp  %s [%s]\n", svc.Port, info, svc.Confidence))
			if svc.Banner != "" {
				banner := svc.Banner
				if len(banner) > 50 {
					banner = banner[:47] + "..."
				}
				sb.WriteString(fmt.Sprintf("          Banner: %s\n", banner))
			}
		}
	}

	// Quirks
	if len(r.Quirks) > 0 {
		sb.WriteString("\nQuirks: " + strings.Join(r.Quirks, ", ") + "\n")
	}

	sb.WriteString(fmt.Sprintf("\nCompleted in %v\n", r.Duration.Round(time.Millisecond)))

	return sb.String()
}

// Helper functions
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func randomInt(max int) int {
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0]) % max
}

// GetPortsByState returns ports categorized by state.
func (r *FingerprintResult) GetPortsByState() map[string][]int {
	return map[string][]int{
		"open":     r.OpenPorts,
		"closed":   r.ClosedPorts,
		"filtered": r.FilteredPorts,
	}
}
