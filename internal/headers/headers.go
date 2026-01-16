// Package headers provides HTTP security headers analysis.
package headers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Severity represents the severity of a security issue.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Issue represents a security issue found in headers.
type Issue struct {
	Header   string
	Severity Severity
	Message  string
	Fix      string
}

// Result holds the security headers analysis result.
type Result struct {
	URL             string
	StatusCode      int
	Headers         map[string]string
	Score           int
	Grade           string
	Issues          []Issue
	Recommendations []string
	Duration        time.Duration
}

// SecurityHeaders defines important security headers to check.
var SecurityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"Cross-Origin-Embedder-Policy",
}

// Analyzer performs security header analysis.
type Analyzer struct {
	Timeout time.Duration
	Client  *http.Client
}

// NewAnalyzer creates a new header analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Timeout: 10 * time.Second,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// Analyze performs security header analysis on the given URL.
func (a *Analyzer) Analyze(ctx context.Context, url string) (*Result, error) {
	start := time.Now()

	// Ensure URL has scheme
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "NNS Security Scanner/1.0")

	// Send request
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	result := &Result{
		URL:             url,
		StatusCode:      resp.StatusCode,
		Headers:         make(map[string]string),
		Issues:          make([]Issue, 0),
		Recommendations: make([]string, 0),
		Duration:        time.Since(start),
	}

	// Extract headers
	for key := range resp.Header {
		result.Headers[key] = resp.Header.Get(key)
	}

	// Analyze headers
	a.analyzeHeaders(result)

	return result, nil
}

// analyzeHeaders checks for security headers and issues.
func (a *Analyzer) analyzeHeaders(result *Result) {
	score := 100

	// Check HSTS
	if hsts := result.Headers["Strict-Transport-Security"]; hsts != "" {
		if !strings.Contains(hsts, "max-age=") {
			result.Issues = append(result.Issues, Issue{
				Header:   "Strict-Transport-Security",
				Severity: SeverityWarning,
				Message:  "HSTS header missing max-age directive",
				Fix:      "Add max-age directive (e.g., max-age=31536000)",
			})
			score -= 5
		} else if !strings.Contains(hsts, "includeSubDomains") {
			result.Issues = append(result.Issues, Issue{
				Header:   "Strict-Transport-Security",
				Severity: SeverityInfo,
				Message:  "HSTS does not include subdomains",
				Fix:      "Add includeSubDomains directive",
			})
			score -= 2
		}
	} else {
		result.Issues = append(result.Issues, Issue{
			Header:   "Strict-Transport-Security",
			Severity: SeverityCritical,
			Message:  "Missing HSTS header - vulnerable to downgrade attacks",
			Fix:      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
		})
		score -= 15
	}

	// Check Content-Security-Policy
	if csp := result.Headers["Content-Security-Policy"]; csp != "" {
		if strings.Contains(csp, "unsafe-inline") {
			result.Issues = append(result.Issues, Issue{
				Header:   "Content-Security-Policy",
				Severity: SeverityWarning,
				Message:  "CSP contains 'unsafe-inline' which weakens XSS protection",
				Fix:      "Use nonces or hashes instead of unsafe-inline",
			})
			score -= 5
		}
		if strings.Contains(csp, "unsafe-eval") {
			result.Issues = append(result.Issues, Issue{
				Header:   "Content-Security-Policy",
				Severity: SeverityWarning,
				Message:  "CSP contains 'unsafe-eval' which allows code injection",
				Fix:      "Remove unsafe-eval and refactor code",
			})
			score -= 5
		}
	} else {
		result.Issues = append(result.Issues, Issue{
			Header:   "Content-Security-Policy",
			Severity: SeverityCritical,
			Message:  "Missing CSP header - vulnerable to XSS attacks",
			Fix:      "Add Content-Security-Policy header with appropriate directives",
		})
		score -= 15
	}

	// Check X-Content-Type-Options
	if xcto := result.Headers["X-Content-Type-Options"]; xcto != "nosniff" {
		result.Issues = append(result.Issues, Issue{
			Header:   "X-Content-Type-Options",
			Severity: SeverityWarning,
			Message:  "Missing or incorrect X-Content-Type-Options",
			Fix:      "Add: X-Content-Type-Options: nosniff",
		})
		score -= 10
	}

	// Check X-Frame-Options
	xfo := result.Headers["X-Frame-Options"]
	if xfo == "" {
		// Check if CSP has frame-ancestors
		csp := result.Headers["Content-Security-Policy"]
		if !strings.Contains(csp, "frame-ancestors") {
			result.Issues = append(result.Issues, Issue{
				Header:   "X-Frame-Options",
				Severity: SeverityWarning,
				Message:  "Missing clickjacking protection",
				Fix:      "Add: X-Frame-Options: DENY or SAMEORIGIN",
			})
			score -= 10
		}
	}

	// Check Referrer-Policy
	if rp := result.Headers["Referrer-Policy"]; rp == "" {
		result.Issues = append(result.Issues, Issue{
			Header:   "Referrer-Policy",
			Severity: SeverityInfo,
			Message:  "Missing Referrer-Policy header",
			Fix:      "Add: Referrer-Policy: strict-origin-when-cross-origin",
		})
		score -= 5
	}

	// Check Permissions-Policy
	if pp := result.Headers["Permissions-Policy"]; pp == "" {
		result.Issues = append(result.Issues, Issue{
			Header:   "Permissions-Policy",
			Severity: SeverityInfo,
			Message:  "Missing Permissions-Policy header",
			Fix:      "Add Permissions-Policy to restrict browser features",
		})
		score -= 3
	}

	// Check for deprecated headers
	if result.Headers["X-XSS-Protection"] != "" {
		result.Issues = append(result.Issues, Issue{
			Header:   "X-XSS-Protection",
			Severity: SeverityInfo,
			Message:  "X-XSS-Protection is deprecated and can cause vulnerabilities",
			Fix:      "Remove X-XSS-Protection header, rely on CSP instead",
		})
	}

	// Check for information disclosure
	if server := result.Headers["Server"]; server != "" {
		if strings.Contains(strings.ToLower(server), "apache") ||
			strings.Contains(strings.ToLower(server), "nginx") ||
			strings.Contains(strings.ToLower(server), "iis") {
			result.Issues = append(result.Issues, Issue{
				Header:   "Server",
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("Server header reveals: %s", server),
				Fix:      "Consider hiding or anonymizing the Server header",
			})
		}
	}

	if xpb := result.Headers["X-Powered-By"]; xpb != "" {
		result.Issues = append(result.Issues, Issue{
			Header:   "X-Powered-By",
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("X-Powered-By reveals technology: %s", xpb),
			Fix:      "Remove X-Powered-By header",
		})
		score -= 5
	}

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	result.Score = score
	result.Grade = calculateGrade(score)
}

// calculateGrade returns a letter grade based on score.
func calculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// GetPresentHeaders returns which security headers are present.
func (r *Result) GetPresentHeaders() []string {
	present := make([]string, 0)
	for _, h := range SecurityHeaders {
		if r.Headers[h] != "" {
			present = append(present, h)
		}
	}
	return present
}

// GetMissingHeaders returns which security headers are missing.
func (r *Result) GetMissingHeaders() []string {
	missing := make([]string, 0)
	for _, h := range SecurityHeaders {
		if r.Headers[h] == "" {
			missing = append(missing, h)
		}
	}
	return missing
}
