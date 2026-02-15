package hashcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashStringMD5(t *testing.T) {
	r := HashString("hello", AlgoMD5)
	if !r.Valid {
		t.Fatalf("expected valid, got error: %s", r.Error)
	}
	if r.Hash != "5d41402abc4b2a76b9719d911017c592" {
		t.Errorf("unexpected MD5: %s", r.Hash)
	}
}

func TestHashStringSHA1(t *testing.T) {
	r := HashString("hello", AlgoSHA1)
	if !r.Valid {
		t.Fatalf("expected valid, got error: %s", r.Error)
	}
	if r.Hash != "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" {
		t.Errorf("unexpected SHA1: %s", r.Hash)
	}
}

func TestHashStringSHA256(t *testing.T) {
	r := HashString("hello", AlgoSHA256)
	if !r.Valid {
		t.Fatalf("expected valid, got error: %s", r.Error)
	}
	if r.Hash != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Errorf("unexpected SHA256: %s", r.Hash)
	}
}

func TestHashStringSHA512(t *testing.T) {
	r := HashString("hello", AlgoSHA512)
	if !r.Valid {
		t.Fatalf("expected valid, got error: %s", r.Error)
	}
	if len(r.Hash) != 128 {
		t.Errorf("SHA512 hash should be 128 hex chars, got %d", len(r.Hash))
	}
}

func TestHashStringUnsupported(t *testing.T) {
	r := HashString("test", Algorithm("unknown"))
	if r.Valid {
		t.Error("expected invalid for unsupported algorithm")
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	r := HashFile(path, AlgoSHA256)
	if !r.Valid {
		t.Fatalf("expected valid, got error: %s", r.Error)
	}
	if r.Hash == "" {
		t.Error("expected non-empty hash")
	}
	if r.Size != 12 {
		t.Errorf("expected size 12, got %d", r.Size)
	}
	if !r.IsFile {
		t.Error("expected IsFile=true")
	}
}

func TestHashFileNotFound(t *testing.T) {
	r := HashFile("/nonexistent/path/file.txt", AlgoSHA256)
	if r.Valid {
		t.Error("expected invalid for missing file")
	}
	if r.Error == "" {
		t.Error("expected error message")
	}
}

func TestHashFileUnsupported(t *testing.T) {
	r := HashFile("somefile", Algorithm("bogus"))
	if r.Valid {
		t.Error("expected invalid for unsupported algorithm")
	}
}

func TestHashAll(t *testing.T) {
	results := HashAll("test")
	if len(results) != len(AllAlgorithms()) {
		t.Errorf("expected %d results, got %d", len(AllAlgorithms()), len(results))
	}
	for _, r := range results {
		if !r.Valid {
			t.Errorf("hash %s failed: %s", r.Algorithm, r.Error)
		}
		if r.Hash == "" {
			t.Errorf("empty hash for %s", r.Algorithm)
		}
	}
}

func TestHashFileAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("file data"), 0644); err != nil {
		t.Fatal(err)
	}

	results := HashFileAll(path)
	if len(results) != len(AllAlgorithms()) {
		t.Errorf("expected %d results, got %d", len(AllAlgorithms()), len(results))
	}
	for _, r := range results {
		if !r.Valid {
			t.Errorf("hash %s failed: %s", r.Algorithm, r.Error)
		}
	}
}

func TestCompareMatch(t *testing.T) {
	r := HashString("hello", AlgoSHA256)
	cr := Compare(r, r.Hash)
	if !cr.Match {
		t.Error("expected match")
	}
}

func TestCompareMismatch(t *testing.T) {
	r := HashString("hello", AlgoSHA256)
	cr := Compare(r, "0000000000000000000000000000000000000000000000000000000000000000")
	if cr.Match {
		t.Error("expected mismatch")
	}
}

func TestCompareCaseInsensitive(t *testing.T) {
	r := HashString("hello", AlgoSHA256)
	cr := Compare(r, strings.ToUpper(r.Hash))
	if !cr.Match {
		t.Error("expected case-insensitive match")
	}
}

func TestCompareTrimsWhitespace(t *testing.T) {
	r := HashString("hello", AlgoSHA256)
	cr := Compare(r, "  "+r.Hash+"  ")
	if !cr.Match {
		t.Error("expected match after trimming whitespace")
	}
}

func TestFormatResult(t *testing.T) {
	r := HashString("test", AlgoSHA256)
	output := FormatResult(r)
	if !strings.Contains(output, "SHA256") {
		t.Error("should contain algorithm name")
	}
	if !strings.Contains(output, "string") {
		t.Error("should indicate string source")
	}
	if !strings.Contains(output, r.Hash) {
		t.Error("should contain hash value")
	}
}

func TestFormatResultFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	os.WriteFile(path, []byte("x"), 0644)
	r := HashFile(path, AlgoMD5)
	output := FormatResult(r)
	if !strings.Contains(output, "file") {
		t.Error("should indicate file source")
	}
}

func TestFormatResultError(t *testing.T) {
	r := HashFile("/no/such/file", AlgoSHA256)
	output := FormatResult(r)
	if !strings.Contains(output, "Error") {
		t.Error("should contain error")
	}
}

func TestFormatCompareMatch(t *testing.T) {
	r := HashString("x", AlgoMD5)
	cr := Compare(r, r.Hash)
	output := FormatCompare(cr)
	if !strings.Contains(output, "MATCH") {
		t.Error("should contain MATCH")
	}
}

func TestFormatCompareMismatch(t *testing.T) {
	r := HashString("x", AlgoMD5)
	cr := Compare(r, "0000")
	output := FormatCompare(cr)
	if !strings.Contains(output, "MISMATCH") {
		t.Error("should contain MISMATCH")
	}
}

func TestAlgorithmBitSize(t *testing.T) {
	tests := []struct {
		algo Algorithm
		bits int
	}{
		{AlgoMD5, 128},
		{AlgoSHA1, 160},
		{AlgoSHA256, 256},
		{AlgoSHA512, 512},
		{Algorithm("unknown"), 0},
	}
	for _, tt := range tests {
		if got := AlgorithmBitSize(tt.algo); got != tt.bits {
			t.Errorf("AlgorithmBitSize(%s) = %d, want %d", tt.algo, got, tt.bits)
		}
	}
}

func TestAllAlgorithms(t *testing.T) {
	algos := AllAlgorithms()
	if len(algos) != 4 {
		t.Errorf("expected 4 algorithms, got %d", len(algos))
	}
}

func TestHashEmptyString(t *testing.T) {
	r := HashString("", AlgoSHA256)
	if !r.Valid {
		t.Fatalf("expected valid, got error: %s", r.Error)
	}
	// SHA256 of empty string is well-known
	if r.Hash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("unexpected SHA256 of empty: %s", r.Hash)
	}
	if r.Size != 0 {
		t.Errorf("expected size 0, got %d", r.Size)
	}
}

func TestHashDuration(t *testing.T) {
	r := HashString("test", AlgoSHA256)
	if r.Duration < 0 {
		t.Error("duration should be non-negative")
	}
}
