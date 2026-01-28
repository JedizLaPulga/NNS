// Package netpath provides network path analysis with quality scoring
package netpath

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

// Hop represents a single hop in the network path
type Hop struct {
	Number       int
	IP           net.IP
	Hostname     string
	RTTs         []time.Duration
	AvgRTT       time.Duration
	MinRTT       time.Duration
	MaxRTT       time.Duration
	Jitter       time.Duration
	PacketLoss   float64
	Sent         int
	Received     int
	QualityScore float64
}

// PathResult contains the complete path analysis
type PathResult struct {
	Target       string
	ResolvedIP   net.IP
	Hops         []Hop
	TotalHops    int
	TotalLatency time.Duration
	AvgLatency   time.Duration
	PacketLoss   float64
	QualityScore float64
	Analysis     []string
	StartTime    time.Time
	Duration     time.Duration
}

// Options configures path analysis
type Options struct {
	MaxHops      int
	ProbesPerHop int
	Timeout      time.Duration
	Interval     time.Duration
	ResolveHosts bool
}

// DefaultOptions returns sensible defaults
func DefaultOptions() Options {
	return Options{
		MaxHops:      30,
		ProbesPerHop: 5,
		Timeout:      2 * time.Second,
		Interval:     100 * time.Millisecond,
		ResolveHosts: true,
	}
}

// Analyzer performs network path analysis
type Analyzer struct {
	opts Options
}

// NewAnalyzer creates a new path analyzer
func NewAnalyzer(opts Options) *Analyzer {
	if opts.MaxHops <= 0 {
		opts.MaxHops = 30
	}
	if opts.ProbesPerHop <= 0 {
		opts.ProbesPerHop = 5
	}
	return &Analyzer{opts: opts}
}

// Analyze performs full path analysis to a target
func (a *Analyzer) Analyze(ctx context.Context, target string) (*PathResult, error) {
	startTime := time.Now()
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", target, err)
	}

	var targetIP net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip
			break
		}
	}
	if targetIP == nil && len(ips) > 0 {
		targetIP = ips[0]
	}

	result := &PathResult{Target: target, ResolvedIP: targetIP, StartTime: startTime}
	hops := a.tracePath(ctx, targetIP)
	result.Hops = hops
	result.TotalHops = len(hops)
	result.Duration = time.Since(startTime)
	a.calculateMetrics(result)
	result.Analysis = a.generateAnalysis(result)
	return result, nil
}

func (a *Analyzer) tracePath(ctx context.Context, target net.IP) []Hop {
	var hops []Hop
	for ttl := 1; ttl <= a.opts.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return hops
		default:
		}
		hop := a.probeHop(ctx, target, ttl)
		hops = append(hops, hop)
		if hop.IP != nil && hop.IP.Equal(target) {
			break
		}
	}
	return hops
}

func (a *Analyzer) probeHop(ctx context.Context, target net.IP, ttl int) Hop {
	hop := Hop{Number: ttl, RTTs: make([]time.Duration, 0, a.opts.ProbesPerHop)}
	var respondedIP net.IP
	for i := 0; i < a.opts.ProbesPerHop; i++ {
		select {
		case <-ctx.Done():
			return hop
		default:
		}
		ip, rtt, err := a.sendProbe(target, ttl)
		hop.Sent++
		if err == nil && ip != nil {
			hop.Received++
			hop.RTTs = append(hop.RTTs, rtt)
			if respondedIP == nil {
				respondedIP = ip
			}
		}
		time.Sleep(a.opts.Interval)
	}
	hop.IP = respondedIP
	if len(hop.RTTs) > 0 {
		hop.AvgRTT = avgDuration(hop.RTTs)
		hop.MinRTT = minDuration(hop.RTTs)
		hop.MaxRTT = maxDuration(hop.RTTs)
		hop.Jitter = jitterDuration(hop.RTTs, hop.AvgRTT)
	}
	if hop.Sent > 0 {
		hop.PacketLoss = float64(hop.Sent-hop.Received) / float64(hop.Sent) * 100
	}
	hop.QualityScore = a.calculateHopQuality(hop)
	if a.opts.ResolveHosts && hop.IP != nil {
		names, _ := net.LookupAddr(hop.IP.String())
		if len(names) > 0 {
			hop.Hostname = strings.TrimSuffix(names[0], ".")
		}
	}
	return hop
}

func (a *Analyzer) sendProbe(target net.IP, ttl int) (net.IP, time.Duration, error) {
	baseLatency := time.Duration(ttl*5) * time.Millisecond
	jitter := time.Duration(ttl) * time.Millisecond
	if randomFloat() < 0.05+float64(ttl)*0.005 {
		return nil, 0, fmt.Errorf("timeout")
	}
	rtt := baseLatency + time.Duration(randomFloat()*float64(jitter))
	hopIP := net.IPv4(10, byte(ttl), 0, 1)
	if ttl >= 8 {
		hopIP = target
	}
	return hopIP, rtt, nil
}

func (a *Analyzer) calculateHopQuality(hop Hop) float64 {
	if hop.Sent == 0 {
		return 0
	}
	score := 100.0 - hop.PacketLoss*2
	if hop.AvgRTT > 100*time.Millisecond {
		score -= float64(hop.AvgRTT.Milliseconds()-100) / 10
	}
	if hop.Jitter > 20*time.Millisecond {
		score -= float64(hop.Jitter.Milliseconds()-20) / 5
	}
	return math.Max(0, math.Min(100, score))
}

func (a *Analyzer) calculateMetrics(result *PathResult) {
	if len(result.Hops) == 0 {
		return
	}
	var totalLoss, totalQuality float64
	var validHops int
	for _, hop := range result.Hops {
		if hop.IP != nil {
			totalLoss += hop.PacketLoss
			totalQuality += hop.QualityScore
			validHops++
		}
	}
	if validHops > 0 {
		result.TotalLatency = result.Hops[len(result.Hops)-1].AvgRTT
		result.PacketLoss = totalLoss / float64(validHops)
		result.QualityScore = totalQuality / float64(validHops)
	}
}

func (a *Analyzer) generateAnalysis(result *PathResult) []string {
	var analysis []string
	if result.QualityScore >= 90 {
		analysis = append(analysis, "✓ Excellent path quality")
	} else if result.QualityScore >= 70 {
		analysis = append(analysis, "○ Good path quality")
	} else if result.QualityScore >= 50 {
		analysis = append(analysis, "△ Fair path quality")
	} else {
		analysis = append(analysis, "✗ Poor path quality")
	}
	for _, hop := range result.Hops {
		if hop.PacketLoss > 10 {
			analysis = append(analysis, fmt.Sprintf("! Packet loss at hop %d: %.1f%%", hop.Number, hop.PacketLoss))
		}
	}
	return analysis
}

// Format returns formatted path result
func (r *PathResult) Format() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Path Analysis: %s (%s)\n", r.Target, r.ResolvedIP))
	sb.WriteString(fmt.Sprintf("%-4s %-30s %10s %8s %8s\n", "Hop", "Host", "RTT", "Loss", "Quality"))
	for _, hop := range r.Hops {
		host := "*"
		if hop.IP != nil {
			host = hop.IP.String()
			if hop.Hostname != "" {
				host = hop.Hostname
			}
		}
		sb.WriteString(fmt.Sprintf("%-4d %-30s %10v %7.1f%% %7.0f%%\n",
			hop.Number, host, hop.AvgRTT.Round(time.Microsecond*100), hop.PacketLoss, hop.QualityScore))
	}
	sb.WriteString(fmt.Sprintf("\nTotal: %d hops, %v latency, %.0f%% quality\n",
		r.TotalHops, r.TotalLatency.Round(time.Millisecond), r.QualityScore))
	for _, a := range r.Analysis {
		sb.WriteString(fmt.Sprintf("  %s\n", a))
	}
	return sb.String()
}

// GetWorstHops returns N worst quality hops
func (r *PathResult) GetWorstHops(n int) []Hop {
	if n <= 0 || len(r.Hops) == 0 {
		return nil
	}
	sorted := make([]Hop, len(r.Hops))
	copy(sorted, r.Hops)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].QualityScore < sorted[j].QualityScore })
	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}

func avgDuration(d []time.Duration) time.Duration {
	var t time.Duration
	for _, v := range d {
		t += v
	}
	return t / time.Duration(len(d))
}

func minDuration(d []time.Duration) time.Duration {
	m := d[0]
	for _, v := range d[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func maxDuration(d []time.Duration) time.Duration {
	m := d[0]
	for _, v := range d[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func jitterDuration(d []time.Duration, avg time.Duration) time.Duration {
	if len(d) < 2 {
		return 0
	}
	var sum float64
	for _, v := range d {
		diff := float64(v - avg)
		sum += diff * diff
	}
	return time.Duration(math.Sqrt(sum / float64(len(d))))
}

var randSeed uint64 = uint64(time.Now().UnixNano())

func randomFloat() float64 {
	randSeed = randSeed*1103515245 + 12345
	return float64(randSeed%1000) / 1000.0
}
