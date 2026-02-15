package passwd

import (
	"strings"
	"testing"
)

func TestAnalyzeStrongPassword(t *testing.T) {
	r := Analyze("P@ssw0rd!Str0ng#2026")
	if r.Strength < Strong {
		t.Errorf("expected Strong or better, got %s", r.StrengthLabel)
	}
	if !r.HasUpper {
		t.Error("should detect uppercase")
	}
	if !r.HasLower {
		t.Error("should detect lowercase")
	}
	if !r.HasDigit {
		t.Error("should detect digits")
	}
	if !r.HasSpecial {
		t.Error("should detect special chars")
	}
}

func TestAnalyzeWeakPassword(t *testing.T) {
	r := Analyze("abc")
	if r.Strength > Weak {
		t.Errorf("expected Weak or worse, got %s", r.StrengthLabel)
	}
	if r.Score > 50 {
		t.Errorf("score should be low for weak password, got %d", r.Score)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze("")
	if r.Strength != VeryWeak {
		t.Errorf("expected VeryWeak for empty, got %s", r.StrengthLabel)
	}
	if r.Entropy != 0 {
		t.Errorf("expected 0 entropy, got %.1f", r.Entropy)
	}
}

func TestAnalyzeAllDigits(t *testing.T) {
	r := Analyze("12345678")
	if r.HasUpper || r.HasLower || r.HasSpecial {
		t.Error("should only detect digits")
	}
	if !r.HasDigit {
		t.Error("should detect digits")
	}
	if r.CharsetSize != 10 {
		t.Errorf("expected charset 10, got %d", r.CharsetSize)
	}
}

func TestAnalyzeCommonWord(t *testing.T) {
	r := Analyze("password123")
	found := false
	for _, issue := range r.Issues {
		if strings.Contains(issue, "common word") {
			found = true
		}
	}
	if !found {
		t.Error("should flag common word 'password'")
	}
}

func TestAnalyzeRepeats(t *testing.T) {
	r := Analyze("aaabbbccc")
	found := false
	for _, issue := range r.Issues {
		if strings.Contains(issue, "repeated") {
			found = true
		}
	}
	if !found {
		t.Error("should flag repeated characters")
	}
}

func TestAnalyzeSequential(t *testing.T) {
	r := Analyze("abcdefgh")
	found := false
	for _, issue := range r.Issues {
		if strings.Contains(issue, "sequential") || strings.Contains(issue, "Sequential") {
			found = true
		}
	}
	if !found {
		t.Error("should flag sequential characters")
	}
}

func TestAnalyzeShortPassword(t *testing.T) {
	r := Analyze("Ab1!")
	found := false
	for _, issue := range r.Issues {
		if strings.Contains(issue, "shorter than 8") {
			found = true
		}
	}
	if !found {
		t.Error("should flag short password")
	}
}

func TestAnalyzeNoIssues(t *testing.T) {
	r := Analyze("Xk9#mPq$7LnR!vWz")
	if len(r.Issues) > 0 {
		t.Errorf("expected no issues for strong random-looking password, got: %v", r.Issues)
	}
}

func TestAnalyzeCrackTime(t *testing.T) {
	weak := Analyze("abc")
	if weak.CrackTime != "Instant" {
		t.Errorf("very weak should be instant, got %s", weak.CrackTime)
	}

	strong := Analyze("Xk9#mPq$7LnR!vWz")
	if strings.Contains(strong.CrackTime, "Instant") {
		t.Error("strong password should not crack instantly")
	}
}

func TestAnalyzeEntropy(t *testing.T) {
	r := Analyze("abcdefghijklmnop")
	if r.Entropy <= 0 {
		t.Error("entropy should be positive")
	}
}

func TestAnalyzeScore(t *testing.T) {
	weak := Analyze("ab")
	strong := Analyze("Xk9#mPq$7LnR!vWz")
	if weak.Score >= strong.Score {
		t.Errorf("weak score (%d) should be less than strong (%d)", weak.Score, strong.Score)
	}
}

func TestGenerate(t *testing.T) {
	opts := DefaultGenerateOptions()
	pw, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != opts.Length {
		t.Errorf("expected length %d, got %d", opts.Length, len(pw))
	}
}

func TestGenerateLength(t *testing.T) {
	opts := DefaultGenerateOptions()
	opts.Length = 32
	pw, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 32 {
		t.Errorf("expected length 32, got %d", len(pw))
	}
}

func TestGenerateNoCharset(t *testing.T) {
	opts := GenerateOptions{Length: 10}
	_, err := Generate(opts)
	if err == nil {
		t.Error("expected error with no charset")
	}
}

func TestGenerateZeroLength(t *testing.T) {
	opts := DefaultGenerateOptions()
	opts.Length = 0
	_, err := Generate(opts)
	if err == nil {
		t.Error("expected error for zero length")
	}
}

func TestGenerateOnlyDigits(t *testing.T) {
	opts := GenerateOptions{
		Length: 20,
		Digits: true,
	}
	pw, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range pw {
		if c < '0' || c > '9' {
			t.Errorf("expected only digits, got %c", c)
		}
	}
}

func TestGenerateExclude(t *testing.T) {
	opts := DefaultGenerateOptions()
	opts.Exclude = "aeiouAEIOU0O1lI"
	opts.Length = 100
	pw, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range pw {
		if strings.ContainsRune(opts.Exclude, c) {
			t.Errorf("password contains excluded character: %c", c)
		}
	}
}

func TestGenerateMultiple(t *testing.T) {
	opts := DefaultGenerateOptions()
	opts.Count = 5
	passwords, err := GenerateMultiple(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(passwords) != 5 {
		t.Errorf("expected 5 passwords, got %d", len(passwords))
	}
}

func TestGenerateMultipleUnique(t *testing.T) {
	opts := DefaultGenerateOptions()
	opts.Length = 32
	opts.Count = 10
	passwords, err := GenerateMultiple(opts)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, pw := range passwords {
		if seen[pw] {
			t.Error("generated duplicate password (very unlikely with 32 chars)")
		}
		seen[pw] = true
	}
}

func TestFormatAnalysis(t *testing.T) {
	r := Analyze("Test@123!")
	output := FormatAnalysis(r)
	if !strings.Contains(output, "Entropy") {
		t.Error("should contain entropy")
	}
	if !strings.Contains(output, "Score") {
		t.Error("should contain score")
	}
	if !strings.Contains(output, "Crack Time") {
		t.Error("should contain crack time")
	}
}

func TestStrengthString(t *testing.T) {
	tests := []struct {
		s    Strength
		want string
	}{
		{VeryWeak, "Very Weak"},
		{Weak, "Weak"},
		{Fair, "Fair"},
		{Strong, "Strong"},
		{VeryStrong, "Very Strong"},
		{Strength(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Strength(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestDefaultGenerateOptions(t *testing.T) {
	opts := DefaultGenerateOptions()
	if opts.Length != 16 {
		t.Errorf("default length should be 16, got %d", opts.Length)
	}
	if !opts.Upper || !opts.Lower || !opts.Digits || !opts.Special {
		t.Error("all charsets should be enabled by default")
	}
}

func TestCharsetSize(t *testing.T) {
	r := Analyze("Aa1!")
	// 26+26+10+33 = 95
	if r.CharsetSize != 95 {
		t.Errorf("expected charset size 95, got %d", r.CharsetSize)
	}
}
