// Package hashcheck provides hashing utilities for strings and files.
package hashcheck

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"time"
)

// Algorithm represents a supported hash algorithm.
type Algorithm string

const (
	AlgoMD5    Algorithm = "md5"
	AlgoSHA1   Algorithm = "sha1"
	AlgoSHA256 Algorithm = "sha256"
	AlgoSHA512 Algorithm = "sha512"
)

// AllAlgorithms returns all supported hash algorithms.
func AllAlgorithms() []Algorithm {
	return []Algorithm{AlgoMD5, AlgoSHA1, AlgoSHA256, AlgoSHA512}
}

// Result holds the result of a hash operation.
type Result struct {
	Input     string        `json:"input"`
	IsFile    bool          `json:"is_file"`
	Algorithm Algorithm     `json:"algorithm"`
	Hash      string        `json:"hash"`
	Size      int64         `json:"size"`
	Duration  time.Duration `json:"duration"`
	Valid     bool          `json:"valid"`
	Error     string        `json:"error,omitempty"`
}

// CompareResult holds the result of a hash comparison.
type CompareResult struct {
	Input1    string    `json:"input1"`
	Input2    string    `json:"input2"`
	Algorithm Algorithm `json:"algorithm"`
	Hash1     string    `json:"hash1"`
	Hash2     string    `json:"hash2"`
	Match     bool      `json:"match"`
	Valid     bool      `json:"valid"`
	Error     string    `json:"error,omitempty"`
}

// newHasher returns a new hash.Hash for the given algorithm.
func newHasher(algo Algorithm) (hash.Hash, error) {
	switch algo {
	case AlgoMD5:
		return md5.New(), nil
	case AlgoSHA1:
		return sha1.New(), nil
	case AlgoSHA256:
		return sha256.New(), nil
	case AlgoSHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}

// HashString computes the hash of a string.
func HashString(input string, algo Algorithm) Result {
	start := time.Now()
	r := Result{
		Input:     input,
		IsFile:    false,
		Algorithm: algo,
		Size:      int64(len(input)),
	}

	h, err := newHasher(algo)
	if err != nil {
		r.Valid = false
		r.Error = err.Error()
		return r
	}

	h.Write([]byte(input))
	r.Hash = hex.EncodeToString(h.Sum(nil))
	r.Valid = true
	r.Duration = time.Since(start)
	return r
}

// HashFile computes the hash of a file.
func HashFile(path string, algo Algorithm) Result {
	start := time.Now()
	r := Result{
		Input:     path,
		IsFile:    true,
		Algorithm: algo,
	}

	h, err := newHasher(algo)
	if err != nil {
		r.Valid = false
		r.Error = err.Error()
		return r
	}

	f, err := os.Open(path)
	if err != nil {
		r.Valid = false
		r.Error = fmt.Sprintf("cannot open file: %v", err)
		return r
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		r.Valid = false
		r.Error = fmt.Sprintf("cannot stat file: %v", err)
		return r
	}
	r.Size = info.Size()

	if _, err := io.Copy(h, f); err != nil {
		r.Valid = false
		r.Error = fmt.Sprintf("read error: %v", err)
		return r
	}

	r.Hash = hex.EncodeToString(h.Sum(nil))
	r.Valid = true
	r.Duration = time.Since(start)
	return r
}

// HashAll computes all supported hashes for a string.
func HashAll(input string) []Result {
	results := make([]Result, 0, len(AllAlgorithms()))
	for _, a := range AllAlgorithms() {
		results = append(results, HashString(input, a))
	}
	return results
}

// HashFileAll computes all supported hashes for a file.
func HashFileAll(path string) []Result {
	results := make([]Result, 0, len(AllAlgorithms()))
	for _, a := range AllAlgorithms() {
		results = append(results, HashFile(path, a))
	}
	return results
}

// Compare compares a computed hash against an expected hash string.
func Compare(computed Result, expected string) CompareResult {
	cr := CompareResult{
		Input1:    computed.Input,
		Input2:    expected,
		Algorithm: computed.Algorithm,
		Hash1:     computed.Hash,
		Hash2:     strings.ToLower(strings.TrimSpace(expected)),
		Valid:     computed.Valid,
		Error:     computed.Error,
	}
	if cr.Valid {
		cr.Match = cr.Hash1 == cr.Hash2
	}
	return cr
}

// FormatResult returns a human-readable representation of a hash result.
func FormatResult(r Result) string {
	var sb strings.Builder

	if r.IsFile {
		sb.WriteString(fmt.Sprintf("  Source:     file: %s\n", r.Input))
	} else {
		sb.WriteString(fmt.Sprintf("  Source:     string\n"))
	}
	sb.WriteString(fmt.Sprintf("  Algorithm:  %s\n", strings.ToUpper(string(r.Algorithm))))
	sb.WriteString(fmt.Sprintf("  Valid:      %v\n", r.Valid))

	if r.Error != "" {
		sb.WriteString(fmt.Sprintf("  Error:      %s\n", r.Error))
		return sb.String()
	}

	if !r.IsFile {
		sb.WriteString(fmt.Sprintf("  Input:      %s\n", truncate(r.Input, 80)))
	}
	sb.WriteString(fmt.Sprintf("  Hash:       %s\n", r.Hash))
	sb.WriteString(fmt.Sprintf("  Size:       %d bytes\n", r.Size))
	sb.WriteString(fmt.Sprintf("  Time:       %s\n", r.Duration.Round(time.Microsecond)))

	return sb.String()
}

// FormatCompare returns a human-readable comparison result.
func FormatCompare(cr CompareResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Algorithm:  %s\n", strings.ToUpper(string(cr.Algorithm))))
	sb.WriteString(fmt.Sprintf("  Computed:   %s\n", cr.Hash1))
	sb.WriteString(fmt.Sprintf("  Expected:   %s\n", cr.Hash2))

	if cr.Match {
		sb.WriteString("  Result:     ✓ MATCH\n")
	} else {
		sb.WriteString("  Result:     ✗ MISMATCH\n")
	}

	return sb.String()
}

// AlgorithmBitSize returns the output bit size for the given algorithm.
func AlgorithmBitSize(algo Algorithm) int {
	switch algo {
	case AlgoMD5:
		return 128
	case AlgoSHA1:
		return 160
	case AlgoSHA256:
		return 256
	case AlgoSHA512:
		return 512
	default:
		return 0
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
