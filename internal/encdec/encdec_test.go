package encdec

import (
	"strings"
	"testing"
)

func TestEncodeBase64(t *testing.T) {
	r := Encode("Hello, World!", FormatBase64)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if r.Output != "SGVsbG8sIFdvcmxkIQ==" {
		t.Errorf("unexpected base64 output: %s", r.Output)
	}
	if r.InSize != 13 {
		t.Errorf("expected input size 13, got %d", r.InSize)
	}
}

func TestDecodeBase64(t *testing.T) {
	r := Decode("SGVsbG8sIFdvcmxkIQ==", FormatBase64)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if r.Output != "Hello, World!" {
		t.Errorf("unexpected decoded output: %s", r.Output)
	}
}

func TestDecodeBase64Invalid(t *testing.T) {
	r := Decode("not-valid-base64!!!", FormatBase64)
	if r.Valid {
		t.Error("expected invalid result for bad base64")
	}
	if r.Error == "" {
		t.Error("expected error message")
	}
}

func TestEncodeBase64URL(t *testing.T) {
	r := Encode("Hello+World/Test=", FormatBase64URL)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if r.Output == "" {
		t.Error("expected non-empty output")
	}
}

func TestDecodeBase64URL(t *testing.T) {
	encoded := Encode("test data", FormatBase64URL)
	decoded := Decode(encoded.Output, FormatBase64URL)
	if !decoded.Valid {
		t.Fatalf("expected valid decode, got error: %s", decoded.Error)
	}
	if decoded.Output != "test data" {
		t.Errorf("roundtrip failed: got %q", decoded.Output)
	}
}

func TestEncodeHex(t *testing.T) {
	r := Encode("ABC", FormatHex)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if r.Output != "414243" {
		t.Errorf("unexpected hex output: %s", r.Output)
	}
}

func TestDecodeHex(t *testing.T) {
	r := Decode("414243", FormatHex)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if r.Output != "ABC" {
		t.Errorf("unexpected decoded hex: %s", r.Output)
	}
}

func TestDecodeHexInvalid(t *testing.T) {
	r := Decode("ZZZZ", FormatHex)
	if r.Valid {
		t.Error("expected invalid result for bad hex")
	}
}

func TestEncodeURL(t *testing.T) {
	r := Encode("hello world&foo=bar", FormatURL)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if !strings.Contains(r.Output, "+") || !strings.Contains(r.Output, "%26") {
		t.Errorf("unexpected URL-encoded output: %s", r.Output)
	}
}

func TestDecodeURL(t *testing.T) {
	r := Decode("hello+world%26foo%3Dbar", FormatURL)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if r.Output != "hello world&foo=bar" {
		t.Errorf("unexpected URL-decoded output: %s", r.Output)
	}
}

func TestEncodeBinary(t *testing.T) {
	r := Encode("AB", FormatBinary)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if r.Output != "01000001 01000010" {
		t.Errorf("unexpected binary output: %s", r.Output)
	}
}

func TestDecodeBinary(t *testing.T) {
	r := Decode("01000001 01000010", FormatBinary)
	if !r.Valid {
		t.Fatalf("expected valid result, got error: %s", r.Error)
	}
	if r.Output != "AB" {
		t.Errorf("unexpected binary decoded: %q", r.Output)
	}
}

func TestDecodeBinaryInvalid(t *testing.T) {
	r := Decode("0100001", FormatBinary)
	if r.Valid {
		t.Error("expected invalid for non-8-bit binary")
	}
}

func TestDecodeBinaryInvalidChars(t *testing.T) {
	r := Decode("01000012", FormatBinary)
	if r.Valid {
		t.Error("expected invalid for non-binary characters")
	}
}

func TestDecodeBinaryEmpty(t *testing.T) {
	r := Decode("   ", FormatBinary)
	if r.Valid {
		t.Error("expected invalid for empty binary")
	}
}

func TestUnsupportedFormat(t *testing.T) {
	r := Encode("test", Format("unknown"))
	if r.Valid {
		t.Error("expected invalid for unsupported format")
	}
	if r.Error == "" {
		t.Error("expected error message for unsupported format")
	}

	r = Decode("test", Format("unknown"))
	if r.Valid {
		t.Error("expected invalid for unsupported format")
	}
}

func TestEncodeAll(t *testing.T) {
	results := EncodeAll("Hello")
	if len(results) != len(AllFormats()) {
		t.Errorf("expected %d results, got %d", len(AllFormats()), len(results))
	}
	for _, r := range results {
		if !r.Valid {
			t.Errorf("encoding %s failed: %s", r.Format, r.Error)
		}
		if r.Output == "" {
			t.Errorf("empty output for format %s", r.Format)
		}
	}
}

func TestDetectFormatHex(t *testing.T) {
	formats := DetectFormat("414243")
	found := false
	for _, f := range formats {
		if f == FormatHex {
			found = true
		}
	}
	if !found {
		t.Error("expected hex to be detected for '414243'")
	}
}

func TestDetectFormatURL(t *testing.T) {
	formats := DetectFormat("hello%20world")
	found := false
	for _, f := range formats {
		if f == FormatURL {
			found = true
		}
	}
	if !found {
		t.Error("expected URL to be detected")
	}
}

func TestDetectFormatBinary(t *testing.T) {
	formats := DetectFormat("01010101 11001100")
	found := false
	for _, f := range formats {
		if f == FormatBinary {
			found = true
		}
	}
	if !found {
		t.Error("expected binary to be detected")
	}
}

func TestDetectFormatEmpty(t *testing.T) {
	formats := DetectFormat("")
	if len(formats) != 0 {
		t.Errorf("expected no formats for empty input, got %d", len(formats))
	}
}

func TestDetectFormatPlainText(t *testing.T) {
	formats := DetectFormat("just some regular text")
	for _, f := range formats {
		if f == FormatBase64 || f == FormatBase64URL {
			t.Errorf("should not detect base64 for plain text, got %s", f)
		}
	}
}

func TestFormatResultEncode(t *testing.T) {
	r := Encode("test", FormatBase64)
	output := FormatResult(r)
	if !strings.Contains(output, "Encode") {
		t.Error("should contain 'Encode' operation")
	}
	if !strings.Contains(output, "base64") {
		t.Error("should contain format name")
	}
	if !strings.Contains(output, "true") {
		t.Error("should show valid=true")
	}
}

func TestFormatResultDecode(t *testing.T) {
	r := Decode("dGVzdA==", FormatBase64)
	output := FormatResult(r)
	if !strings.Contains(output, "Decode") {
		t.Error("should contain 'Decode' operation")
	}
}

func TestFormatResultError(t *testing.T) {
	r := Decode("!!!", FormatHex)
	output := FormatResult(r)
	if !strings.Contains(output, "Error") {
		t.Error("should contain error in formatted output")
	}
}

func TestFormatDetectionWithResults(t *testing.T) {
	formats := DetectFormat("414243")
	output := FormatDetection("414243", formats)
	if !strings.Contains(output, "414243") {
		t.Error("should contain input")
	}
	if !strings.Contains(output, "hex") {
		t.Error("should show hex as detected format")
	}
}

func TestFormatDetectionNoFormats(t *testing.T) {
	output := FormatDetection("plain text", nil)
	if !strings.Contains(output, "none") {
		t.Error("should indicate no formats detected")
	}
}

func TestRoundTrip(t *testing.T) {
	input := "The quick brown fox jumps over the lazy dog 🦊"
	for _, f := range AllFormats() {
		encoded := Encode(input, f)
		if !encoded.Valid {
			t.Errorf("encode %s failed: %s", f, encoded.Error)
			continue
		}
		decoded := Decode(encoded.Output, f)
		if !decoded.Valid {
			t.Errorf("decode %s failed: %s", f, decoded.Error)
			continue
		}
		if decoded.Output != input {
			t.Errorf("roundtrip %s failed: got %q", f, decoded.Output)
		}
	}
}

func TestAllFormats(t *testing.T) {
	formats := AllFormats()
	if len(formats) != 5 {
		t.Errorf("expected 5 formats, got %d", len(formats))
	}
}

func TestTruncate(t *testing.T) {
	short := "hello"
	if truncate(short, 10) != "hello" {
		t.Error("should not truncate short strings")
	}
	long := strings.Repeat("a", 100)
	result := truncate(long, 10)
	if len(result) != 13 { // 10 + "..."
		t.Errorf("truncated length should be 13, got %d", len(result))
	}
}
