package httpclient

import (
	"testing"
	"time"
)

func TestParseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"api.example.com/v1", "https://api.example.com/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseURL(tt.input)
			if got != tt.want {
				t.Errorf("ParseURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatSize(tt.bytes)
			if got != tt.want {
				t.Errorf("FormatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	c := NewClient()

	if c.Timeout == 0 {
		t.Error("NewClient().Timeout should not be zero")
	}

	if !c.FollowRedirects {
		t.Error("NewClient().FollowRedirects should be true by default")
	}

	if c.MaxBodySize == 0 {
		t.Error("NewClient().MaxBodySize should not be zero")
	}
}

func TestClientDo(t *testing.T) {
	c := NewClient()
	c.Timeout = 10 * time.Second

	req := &Request{
		Method: "GET",
		URL:    "https://httpbin.org/get",
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Skipf("Network issue: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}

	if resp.Timing.Total == 0 {
		t.Error("Timing.Total should not be zero")
	}

	if len(resp.Body) == 0 {
		t.Error("Body should not be empty")
	}
}

func TestClientDoWithHeaders(t *testing.T) {
	c := NewClient()
	c.Timeout = 10 * time.Second

	req := &Request{
		Method: "GET",
		URL:    "https://httpbin.org/headers",
		Headers: map[string]string{
			"X-Test-Header": "test-value",
		},
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Skipf("Network issue: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestClientDoPost(t *testing.T) {
	c := NewClient()
	c.Timeout = 10 * time.Second

	req := &Request{
		Method: "POST",
		URL:    "https://httpbin.org/post",
		Body:   "test=value",
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Skipf("Network issue: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestResponseIsSuccess(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{200, true},
		{201, true},
		{204, true},
		{301, false},
		{404, false},
		{500, false},
	}

	for _, tt := range tests {
		resp := &Response{StatusCode: tt.code}
		if got := resp.IsSuccess(); got != tt.want {
			t.Errorf("IsSuccess() for %d = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestResponseIsRedirect(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{200, false},
		{301, true},
		{302, true},
		{307, true},
		{404, false},
	}

	for _, tt := range tests {
		resp := &Response{StatusCode: tt.code}
		if got := resp.IsRedirect(); got != tt.want {
			t.Errorf("IsRedirect() for %d = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func BenchmarkDo(b *testing.B) {
	c := NewClient()
	req := &Request{
		Method: "GET",
		URL:    "https://httpbin.org/get",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Do(req)
	}
}
