// Package passwd provides password strength analysis and secure generation.
package passwd

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"strings"
	"unicode"
)

// Strength represents password strength level.
type Strength int

const (
	VeryWeak   Strength = iota // 0-19 bits
	Weak                       // 20-39 bits
	Fair                       // 40-59 bits
	Strong                     // 60-79 bits
	VeryStrong                 // 80+ bits
)

// String returns the human-readable strength label.
func (s Strength) String() string {
	switch s {
	case VeryWeak:
		return "Very Weak"
	case Weak:
		return "Weak"
	case Fair:
		return "Fair"
	case Strong:
		return "Strong"
	case VeryStrong:
		return "Very Strong"
	default:
		return "Unknown"
	}
}

// AnalysisResult holds the results of a password strength analysis.
type AnalysisResult struct {
	Password      string   `json:"-"`
	Length        int      `json:"length"`
	Entropy       float64  `json:"entropy"`
	Strength      Strength `json:"strength"`
	StrengthLabel string   `json:"strength_label"`
	CrackTime     string   `json:"crack_time"`
	HasUpper      bool     `json:"has_upper"`
	HasLower      bool     `json:"has_lower"`
	HasDigit      bool     `json:"has_digit"`
	HasSpecial    bool     `json:"has_special"`
	HasUnicode    bool     `json:"has_unicode"`
	CharsetSize   int      `json:"charset_size"`
	Issues        []string `json:"issues,omitempty"`
	Score         int      `json:"score"`
}

// GenerateOptions configures password generation.
type GenerateOptions struct {
	Length  int
	Upper   bool
	Lower   bool
	Digits  bool
	Special bool
	Exclude string
	Count   int
}

// DefaultGenerateOptions returns sensible defaults.
func DefaultGenerateOptions() GenerateOptions {
	return GenerateOptions{
		Length:  16,
		Upper:   true,
		Lower:   true,
		Digits:  true,
		Special: true,
		Count:   1,
	}
}

// Analyze performs a comprehensive password strength analysis.
func Analyze(password string) AnalysisResult {
	r := AnalysisResult{
		Password: password,
		Length:   len(password),
	}

	for _, c := range password {
		if unicode.IsUpper(c) {
			r.HasUpper = true
		} else if unicode.IsLower(c) {
			r.HasLower = true
		} else if unicode.IsDigit(c) {
			r.HasDigit = true
		} else if c > 127 {
			r.HasUnicode = true
		} else {
			r.HasSpecial = true
		}
	}

	// Compute charset size
	r.CharsetSize = charsetSize(r)

	// Compute entropy: log2(charset^length)
	if r.CharsetSize > 0 && r.Length > 0 {
		r.Entropy = float64(r.Length) * math.Log2(float64(r.CharsetSize))
	}

	// Determine strength
	switch {
	case r.Entropy >= 80:
		r.Strength = VeryStrong
	case r.Entropy >= 60:
		r.Strength = Strong
	case r.Entropy >= 40:
		r.Strength = Fair
	case r.Entropy >= 20:
		r.Strength = Weak
	default:
		r.Strength = VeryWeak
	}
	r.StrengthLabel = r.Strength.String()

	// Crack time estimation (10 billion guesses/sec)
	r.CrackTime = estimateCrackTime(r.Entropy)

	// Issues
	r.Issues = findIssues(password, r)

	// Score (0-100)
	r.Score = computeScore(r)

	return r
}

// Generate creates a cryptographically random password.
func Generate(opts GenerateOptions) (string, error) {
	charset := buildCharset(opts)
	if len(charset) == 0 {
		return "", fmt.Errorf("no characters available for generation")
	}

	if opts.Length < 1 {
		return "", fmt.Errorf("length must be at least 1")
	}

	result := make([]byte, opts.Length)
	for i := range result {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("random generation failed: %v", err)
		}
		result[i] = charset[idx.Int64()]
	}

	return string(result), nil
}

// GenerateMultiple creates multiple passwords.
func GenerateMultiple(opts GenerateOptions) ([]string, error) {
	if opts.Count < 1 {
		opts.Count = 1
	}
	passwords := make([]string, 0, opts.Count)
	for i := 0; i < opts.Count; i++ {
		pw, err := Generate(opts)
		if err != nil {
			return nil, err
		}
		passwords = append(passwords, pw)
	}
	return passwords, nil
}

// FormatAnalysis returns a human-readable analysis report.
func FormatAnalysis(r AnalysisResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Length:       %d characters\n", r.Length))
	sb.WriteString(fmt.Sprintf("  Entropy:     %.1f bits\n", r.Entropy))
	sb.WriteString(fmt.Sprintf("  Strength:    %s\n", r.StrengthLabel))
	sb.WriteString(fmt.Sprintf("  Score:       %d/100\n", r.Score))
	sb.WriteString(fmt.Sprintf("  Crack Time:  %s\n", r.CrackTime))
	sb.WriteString(fmt.Sprintf("  Charset:     %d characters\n", r.CharsetSize))
	sb.WriteString("\n  Character Types:\n")
	sb.WriteString(fmt.Sprintf("    Uppercase:   %s\n", boolIcon(r.HasUpper)))
	sb.WriteString(fmt.Sprintf("    Lowercase:   %s\n", boolIcon(r.HasLower)))
	sb.WriteString(fmt.Sprintf("    Digits:      %s\n", boolIcon(r.HasDigit)))
	sb.WriteString(fmt.Sprintf("    Special:     %s\n", boolIcon(r.HasSpecial)))

	if len(r.Issues) > 0 {
		sb.WriteString("\n  Issues:\n")
		for _, issue := range r.Issues {
			sb.WriteString(fmt.Sprintf("    ⚠ %s\n", issue))
		}
	}

	return sb.String()
}

// --- helpers ---

func charsetSize(r AnalysisResult) int {
	size := 0
	if r.HasUpper {
		size += 26
	}
	if r.HasLower {
		size += 26
	}
	if r.HasDigit {
		size += 10
	}
	if r.HasSpecial {
		size += 33
	}
	if r.HasUnicode {
		size += 100
	}
	return size
}

func estimateCrackTime(entropy float64) string {
	// 10 billion (1e10) guesses per second
	seconds := math.Pow(2, entropy) / 1e10

	switch {
	case seconds < 1:
		return "Instant"
	case seconds < 60:
		return fmt.Sprintf("%.0f seconds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%.0f minutes", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%.0f hours", seconds/3600)
	case seconds < 86400*365:
		return fmt.Sprintf("%.0f days", seconds/86400)
	case seconds < 86400*365*1000:
		return fmt.Sprintf("%.0f years", seconds/(86400*365))
	case seconds < 86400*365*1e6:
		return fmt.Sprintf("%.0f thousand years", seconds/(86400*365*1000))
	case seconds < 86400*365*1e9:
		return fmt.Sprintf("%.0f million years", seconds/(86400*365*1e6))
	default:
		return fmt.Sprintf("%.0e years", seconds/(86400*365))
	}
}

func findIssues(password string, r AnalysisResult) []string {
	var issues []string

	if r.Length < 8 {
		issues = append(issues, "Password is shorter than 8 characters")
	}
	if !r.HasUpper {
		issues = append(issues, "No uppercase letters")
	}
	if !r.HasLower {
		issues = append(issues, "No lowercase letters")
	}
	if !r.HasDigit {
		issues = append(issues, "No digits")
	}
	if !r.HasSpecial {
		issues = append(issues, "No special characters")
	}

	// Check for repeated characters
	if hasRepeats(password, 3) {
		issues = append(issues, "Contains 3+ repeated characters in a row")
	}

	// Check for sequential characters
	if hasSequential(password, 3) {
		issues = append(issues, "Contains sequential characters (abc, 123, etc.)")
	}

	// Common patterns
	lower := strings.ToLower(password)
	commonWords := []string{"password", "qwerty", "letmein", "admin", "welcome", "monkey", "dragon", "master", "login"}
	for _, w := range commonWords {
		if strings.Contains(lower, w) {
			issues = append(issues, fmt.Sprintf("Contains common word: %q", w))
			break
		}
	}

	return issues
}

func hasRepeats(s string, minRun int) bool {
	if len(s) < minRun {
		return false
	}
	count := 1
	prev := rune(0)
	for _, c := range s {
		if c == prev {
			count++
			if count >= minRun {
				return true
			}
		} else {
			count = 1
		}
		prev = c
	}
	return false
}

func hasSequential(s string, minRun int) bool {
	if len(s) < minRun {
		return false
	}
	runes := []rune(s)
	ascending := 1
	descending := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1]+1 {
			ascending++
			if ascending >= minRun {
				return true
			}
		} else {
			ascending = 1
		}
		if runes[i] == runes[i-1]-1 {
			descending++
			if descending >= minRun {
				return true
			}
		} else {
			descending = 1
		}
	}
	return false
}

func computeScore(r AnalysisResult) int {
	score := 0

	// Length contribution (up to 30 points)
	lengthScore := r.Length * 3
	if lengthScore > 30 {
		lengthScore = 30
	}
	score += lengthScore

	// Charset diversity (up to 20 points)
	types := 0
	if r.HasUpper {
		types++
	}
	if r.HasLower {
		types++
	}
	if r.HasDigit {
		types++
	}
	if r.HasSpecial {
		types++
	}
	score += types * 5

	// Entropy contribution (up to 40 points)
	entropyScore := int(r.Entropy / 2)
	if entropyScore > 40 {
		entropyScore = 40
	}
	score += entropyScore

	// Penalty for issues
	score -= len(r.Issues) * 3
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

func boolIcon(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}

func buildCharset(opts GenerateOptions) []byte {
	var charset []byte
	if opts.Upper {
		charset = append(charset, []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")...)
	}
	if opts.Lower {
		charset = append(charset, []byte("abcdefghijklmnopqrstuvwxyz")...)
	}
	if opts.Digits {
		charset = append(charset, []byte("0123456789")...)
	}
	if opts.Special {
		charset = append(charset, []byte("!@#$%^&*()-_=+[]{}|;:,.<>?/~`")...)
	}

	if opts.Exclude != "" {
		filtered := make([]byte, 0, len(charset))
		for _, c := range charset {
			if !strings.ContainsRune(opts.Exclude, rune(c)) {
				filtered = append(filtered, c)
			}
		}
		charset = filtered
	}

	return charset
}
