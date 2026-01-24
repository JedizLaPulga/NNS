// Package dnstrace provides DNS resolution chain tracing.
package dnstrace

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// RootServers contains the list of DNS root servers.
var RootServers = []string{
	"a.root-servers.net", // Verisign
	"b.root-servers.net", // USC-ISI
	"c.root-servers.net", // Cogent
	"d.root-servers.net", // UMD
	"e.root-servers.net", // NASA
	"f.root-servers.net", // ISC
	"g.root-servers.net", // DISA
	"h.root-servers.net", // ARL
	"i.root-servers.net", // Netnod
	"j.root-servers.net", // Verisign
	"k.root-servers.net", // RIPE
	"l.root-servers.net", // ICANN
	"m.root-servers.net", // WIDE
}

// Step represents a single step in the DNS resolution chain.
type Step struct {
	Level      int           // 0=root, 1=TLD, 2=authoritative, etc.
	ServerName string        // Name of the DNS server
	ServerIP   string        // IP address of the DNS server
	Query      string        // Query sent
	QueryType  string        // A, NS, etc.
	Answers    []string      // Answers received
	Referrals  []string      // NS referrals (delegation)
	Duration   time.Duration // Time taken for this query
	Error      error         // Error if any
}

// Trace represents a complete DNS resolution trace.
type Trace struct {
	Target    string
	QueryType string
	Steps     []Step
	FinalIPs  []string
	TotalTime time.Duration
	Success   bool
	Error     error
}

// Config holds configuration for the tracer.
type Config struct {
	Timeout     time.Duration
	MaxDepth    int
	QueryType   string // A, AAAA, MX, etc.
	StartServer string // Custom starting server (default: root)
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:   5 * time.Second,
		MaxDepth:  10,
		QueryType: "A",
	}
}

// Tracer performs DNS resolution tracing.
type Tracer struct {
	config Config
}

// New creates a new Tracer with the given configuration.
func New(cfg Config) *Tracer {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 10
	}
	if cfg.QueryType == "" {
		cfg.QueryType = "A"
	}
	return &Tracer{config: cfg}
}

// TraceResolution traces the DNS resolution chain for a domain.
func (t *Tracer) TraceResolution(ctx context.Context, domain string, callback func(Step)) (*Trace, error) {
	trace := &Trace{
		Target:    domain,
		QueryType: t.config.QueryType,
		Steps:     make([]Step, 0),
	}

	startTime := time.Now()
	domain = strings.TrimSuffix(domain, ".") + "."

	// Determine starting point
	var currentServers []string
	if t.config.StartServer != "" {
		currentServers = []string{t.config.StartServer}
	} else {
		currentServers = []string{RootServers[0]}
	}

	level := 0
	visited := make(map[string]bool)

	for level < t.config.MaxDepth {
		select {
		case <-ctx.Done():
			trace.Error = ctx.Err()
			return trace, ctx.Err()
		default:
		}

		if len(currentServers) == 0 {
			break
		}

		serverName := currentServers[0]

		// Skip if already visited
		if visited[serverName] {
			currentServers = currentServers[1:]
			continue
		}
		visited[serverName] = true

		// Resolve server IP if needed
		serverIP := serverName
		if net.ParseIP(serverName) == nil {
			ips, err := net.LookupIP(serverName)
			if err != nil || len(ips) == 0 {
				step := Step{
					Level:      level,
					ServerName: serverName,
					Query:      domain,
					Error:      fmt.Errorf("failed to resolve server %s: %v", serverName, err),
				}
				trace.Steps = append(trace.Steps, step)
				if callback != nil {
					callback(step)
				}
				currentServers = currentServers[1:]
				continue
			}
			serverIP = ips[0].String()
		}

		// Query the server
		step := t.queryServer(ctx, serverName, serverIP, domain, level)
		trace.Steps = append(trace.Steps, step)
		if callback != nil {
			callback(step)
		}

		if step.Error != nil {
			currentServers = currentServers[1:]
			continue
		}

		// Check if we got final answers (A/AAAA records)
		if len(step.Answers) > 0 && (t.config.QueryType == "A" || t.config.QueryType == "AAAA") {
			trace.FinalIPs = step.Answers
			trace.Success = true
			break
		}

		// Check if we got referrals (NS records)
		if len(step.Referrals) > 0 {
			currentServers = step.Referrals
			level++
		} else if len(step.Answers) > 0 {
			// Got answers for other record types
			trace.FinalIPs = step.Answers
			trace.Success = true
			break
		} else {
			// No referrals and no answers, try next server
			currentServers = currentServers[1:]
		}
	}

	trace.TotalTime = time.Since(startTime)
	return trace, nil
}

// queryServer queries a specific DNS server.
func (t *Tracer) queryServer(ctx context.Context, serverName, serverIP, domain string, level int) Step {
	step := Step{
		Level:      level,
		ServerName: serverName,
		ServerIP:   serverIP,
		Query:      domain,
		QueryType:  t.config.QueryType,
	}

	start := time.Now()

	// Create custom resolver using this specific server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: t.config.Timeout}
			return d.DialContext(ctx, "udp", serverIP+":53")
		},
	}

	// Query based on type
	switch strings.ToUpper(t.config.QueryType) {
	case "A":
		ips, err := resolver.LookupIP(ctx, "ip4", strings.TrimSuffix(domain, "."))
		if err != nil {
			// Try to get NS referrals
			ns, nsErr := resolver.LookupNS(ctx, strings.TrimSuffix(domain, "."))
			if nsErr == nil && len(ns) > 0 {
				for _, n := range ns {
					step.Referrals = append(step.Referrals, n.Host)
				}
			} else {
				// Try parent domain for referrals
				parts := strings.SplitN(strings.TrimSuffix(domain, "."), ".", 2)
				if len(parts) > 1 {
					ns, nsErr = resolver.LookupNS(ctx, parts[1])
					if nsErr == nil && len(ns) > 0 {
						for _, n := range ns {
							step.Referrals = append(step.Referrals, n.Host)
						}
					}
				}
			}
			if len(step.Referrals) == 0 {
				step.Error = err
			}
		} else {
			for _, ip := range ips {
				step.Answers = append(step.Answers, ip.String())
			}
		}

	case "AAAA":
		ips, err := resolver.LookupIP(ctx, "ip6", strings.TrimSuffix(domain, "."))
		if err != nil {
			step.Error = err
		} else {
			for _, ip := range ips {
				step.Answers = append(step.Answers, ip.String())
			}
		}

	case "MX":
		mxs, err := resolver.LookupMX(ctx, strings.TrimSuffix(domain, "."))
		if err != nil {
			step.Error = err
		} else {
			for _, mx := range mxs {
				step.Answers = append(step.Answers, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
			}
		}

	case "NS":
		nss, err := resolver.LookupNS(ctx, strings.TrimSuffix(domain, "."))
		if err != nil {
			step.Error = err
		} else {
			for _, ns := range nss {
				step.Answers = append(step.Answers, ns.Host)
			}
		}

	case "TXT":
		txts, err := resolver.LookupTXT(ctx, strings.TrimSuffix(domain, "."))
		if err != nil {
			step.Error = err
		} else {
			step.Answers = txts
		}

	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, strings.TrimSuffix(domain, "."))
		if err != nil {
			step.Error = err
		} else {
			step.Answers = []string{cname}
		}

	default:
		step.Error = fmt.Errorf("unsupported query type: %s", t.config.QueryType)
	}

	step.Duration = time.Since(start)
	return step
}

// QuickTrace performs a simple trace and returns the result.
func QuickTrace(ctx context.Context, domain string) (*Trace, error) {
	tracer := New(DefaultConfig())
	return tracer.TraceResolution(ctx, domain, nil)
}

// FormatStep formats a step for display.
func FormatStep(s Step) string {
	levelNames := []string{"ROOT", "TLD", "AUTH", "AUTH2", "AUTH3"}
	levelName := "AUTH"
	if s.Level < len(levelNames) {
		levelName = levelNames[s.Level]
	}

	status := "✓"
	if s.Error != nil {
		status = "✕"
	}

	var result string
	if len(s.Answers) > 0 {
		result = strings.Join(s.Answers, ", ")
	} else if len(s.Referrals) > 0 {
		result = fmt.Sprintf("→ %s", strings.Join(s.Referrals, ", "))
	} else if s.Error != nil {
		result = s.Error.Error()
	} else {
		result = "-"
	}

	return fmt.Sprintf("%s [%5s] %-30s %8.2fms  %s",
		status, levelName, s.ServerName,
		float64(s.Duration.Microseconds())/1000.0, result)
}

// FormatTrace formats a complete trace for display.
func FormatTrace(t *Trace) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DNS Trace: %s (%s)\n", t.Target, t.QueryType))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, step := range t.Steps {
		sb.WriteString(FormatStep(step) + "\n")
	}

	sb.WriteString(strings.Repeat("-", 80) + "\n")

	if t.Success {
		sb.WriteString(fmt.Sprintf("✓ Resolved: %s\n", strings.Join(t.FinalIPs, ", ")))
	} else if t.Error != nil {
		sb.WriteString(fmt.Sprintf("✕ Failed: %v\n", t.Error))
	} else {
		sb.WriteString("✕ Resolution incomplete\n")
	}

	sb.WriteString(fmt.Sprintf("Total time: %.2fms (%d steps)\n",
		float64(t.TotalTime.Microseconds())/1000.0, len(t.Steps)))

	return sb.String()
}
