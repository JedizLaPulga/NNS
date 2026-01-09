package bench

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBenchmarks(t *testing.T) {
	// Start a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond) // Simulate latency
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, Benchmark!"))
	}))
	defer ts.Close()

	t.Run("RequestCountMode", func(t *testing.T) {
		cfg := Config{
			URL:          ts.URL,
			Method:       "GET",
			RequestCount: 10,
			Concurrency:  2,
			Timeout:      1 * time.Second,
		}

		summary := Run(context.Background(), cfg)

		if summary.TotalRequests != 10 {
			t.Errorf("TotalRequests = %d, want 10", summary.TotalRequests)
		}

		if summary.SuccessCount != 10 {
			t.Errorf("SuccessCount = %d, want 10", summary.SuccessCount)
		}

		if summary.RequestsPerSec == 0 {
			t.Error("RequestsPerSec should be > 0")
		}

		if summary.P50Lat == 0 {
			t.Error("P50Lat should be > 0")
		}
	})

	t.Run("DurationMode", func(t *testing.T) {
		cfg := Config{
			URL:         ts.URL,
			Method:      "GET",
			Duration:    200 * time.Millisecond,
			Concurrency: 5,
			Timeout:     1 * time.Second,
		}

		summary := Run(context.Background(), cfg)

		if summary.TotalRequests == 0 {
			t.Error("TotalRequests should be > 0")
		}

		if summary.TotalDuration < 200*time.Millisecond {
			t.Errorf("TotalDuration = %v, want >= 200ms", summary.TotalDuration)
		}
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Connect to closed port
		cfg := Config{
			URL:          "http://127.0.0.1:54321",
			Method:       "GET",
			RequestCount: 1,
			Concurrency:  1,
			Timeout:      100 * time.Millisecond,
		}

		summary := Run(context.Background(), cfg)

		if summary.ErrorCount != 1 {
			t.Errorf("ErrorCount = %d, want 1", summary.ErrorCount)
		}
	})
}
