package ipconv

import (
	"strings"
	"testing"
)

func TestConvertIPv4(t *testing.T) {
	c := Convert("192.168.1.1")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if c.Decimal != "192.168.1.1" {
		t.Errorf("unexpected decimal: %s", c.Decimal)
	}
	if c.IsIPv6 {
		t.Error("should be IPv4")
	}
}

func TestConvertIPv4Hex(t *testing.T) {
	c := Convert("192.168.1.1")
	if c.Hex != "0xc0.0xa8.0x01.0x01" {
		t.Errorf("unexpected hex: %s", c.Hex)
	}
	if c.HexCompact != "0xc0a80101" {
		t.Errorf("unexpected hex compact: %s", c.HexCompact)
	}
}

func TestConvertIPv4Octal(t *testing.T) {
	c := Convert("192.168.1.1")
	if c.Octal != "0300.0250.0001.0001" {
		t.Errorf("unexpected octal: %s", c.Octal)
	}
}

func TestConvertIPv4Binary(t *testing.T) {
	c := Convert("192.168.1.1")
	if c.Binary != "11000000.10101000.00000001.00000001" {
		t.Errorf("unexpected binary: %s", c.Binary)
	}
}

func TestConvertIPv4Integer(t *testing.T) {
	c := Convert("192.168.1.1")
	if c.Integer != "3232235777" {
		t.Errorf("unexpected integer: %s", c.Integer)
	}
}

func TestConvertIPv4Mapped(t *testing.T) {
	c := Convert("10.0.0.1")
	if c.Mapped != "::ffff:10.0.0.1" {
		t.Errorf("unexpected mapped: %s", c.Mapped)
	}
}

func TestConvertIPv4Reverse(t *testing.T) {
	c := Convert("192.168.1.1")
	if c.Reverse != "1.1.168.192.in-addr.arpa" {
		t.Errorf("unexpected reverse: %s", c.Reverse)
	}
}

func TestConvertIPv6(t *testing.T) {
	c := Convert("::1")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if !c.IsIPv6 {
		t.Error("should be IPv6")
	}
	if c.Integer != "1" {
		t.Errorf("unexpected integer: %s", c.Integer)
	}
}

func TestConvertIPv6FullReverse(t *testing.T) {
	c := Convert("::1")
	if !strings.HasSuffix(c.Reverse, ".ip6.arpa") {
		t.Errorf("reverse should end with .ip6.arpa: %s", c.Reverse)
	}
}

func TestConvertInvalid(t *testing.T) {
	c := Convert("not-an-ip")
	if c.Valid {
		t.Error("expected invalid")
	}
	if c.Error == "" {
		t.Error("expected error message")
	}
}

func TestConvertFromHexCompact(t *testing.T) {
	c := Convert("0xC0A80101")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if c.Decimal != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", c.Decimal)
	}
}

func TestConvertFromHexDotted(t *testing.T) {
	c := Convert("0xC0.0xA8.0x01.0x01")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if c.Decimal != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", c.Decimal)
	}
}

func TestConvertFromInteger(t *testing.T) {
	c := FromInteger("3232235777")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if c.Decimal != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", c.Decimal)
	}
}

func TestFromIntegerZero(t *testing.T) {
	c := FromInteger("0")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if c.Decimal != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0, got %s", c.Decimal)
	}
}

func TestFromIntegerNegative(t *testing.T) {
	c := FromInteger("-1")
	if c.Valid {
		t.Error("expected invalid for negative")
	}
}

func TestFromIntegerTooLarge(t *testing.T) {
	c := FromInteger("999999999999999999999999999999999999999999")
	if c.Valid {
		t.Error("expected invalid for too-large integer")
	}
}

func TestFromIntegerInvalidString(t *testing.T) {
	c := FromInteger("notanumber")
	if c.Valid {
		t.Error("expected invalid")
	}
}

func TestFromIntegerIPv6Range(t *testing.T) {
	c := FromInteger("4294967296")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if !c.IsIPv6 {
		t.Error("expected IPv6 for value > 2^32")
	}
}

func TestConvertFromOctalDotted(t *testing.T) {
	c := Convert("0300.0250.0001.0001")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if c.Decimal != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", c.Decimal)
	}
}

func TestConvertFromPureInteger(t *testing.T) {
	c := Convert("3232235777")
	if !c.Valid {
		t.Fatalf("expected valid, got: %s", c.Error)
	}
	if c.Decimal != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", c.Decimal)
	}
}

func TestConvertLoopback(t *testing.T) {
	c := Convert("127.0.0.1")
	if !c.Valid {
		t.Fatal("expected valid")
	}
	if c.Integer != "2130706433" {
		t.Errorf("unexpected integer for loopback: %s", c.Integer)
	}
}

func TestConvertAllZeros(t *testing.T) {
	c := Convert("0.0.0.0")
	if !c.Valid {
		t.Fatal("expected valid")
	}
	if c.Integer != "0" {
		t.Errorf("unexpected integer: %s", c.Integer)
	}
	if c.Binary != "00000000.00000000.00000000.00000000" {
		t.Errorf("unexpected binary: %s", c.Binary)
	}
}

func TestConvertBroadcast(t *testing.T) {
	c := Convert("255.255.255.255")
	if !c.Valid {
		t.Fatal("expected valid")
	}
	if c.Integer != "4294967295" {
		t.Errorf("unexpected integer: %s", c.Integer)
	}
}

func TestFormatConversionValid(t *testing.T) {
	c := Convert("10.0.0.1")
	out := FormatConversion(c)
	if !strings.Contains(out, "10.0.0.1") {
		t.Error("should contain decimal")
	}
	if !strings.Contains(out, "IPv4") {
		t.Error("should contain type")
	}
	if !strings.Contains(out, "Hex") {
		t.Error("should contain hex label")
	}
}

func TestFormatConversionInvalid(t *testing.T) {
	c := Convert("garbage")
	out := FormatConversion(c)
	if !strings.Contains(out, "Error") {
		t.Error("should contain error")
	}
}

func TestAllFormats(t *testing.T) {
	fmts := AllFormats()
	if len(fmts) != 6 {
		t.Errorf("expected 6 formats, got %d", len(fmts))
	}
}

func TestConvertWhitespace(t *testing.T) {
	c := Convert("  192.168.1.1  ")
	if !c.Valid {
		t.Fatalf("should handle whitespace, got: %s", c.Error)
	}
}

func TestConvertIPv6Full(t *testing.T) {
	c := Convert("2001:db8::1")
	if !c.Valid {
		t.Fatalf("expected valid, got error: %s", c.Error)
	}
	if !c.IsIPv6 {
		t.Error("should be IPv6")
	}
	if c.Mapped != "" {
		t.Error("IPv6 should not have mapped")
	}
}
