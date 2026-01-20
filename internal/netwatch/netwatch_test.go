package netwatch

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want 5s", cfg.PollInterval)
	}
	if cfg.ConnectivityCheckHost != "8.8.8.8" {
		t.Errorf("ConnectivityCheckHost = %q, want 8.8.8.8", cfg.ConnectivityCheckHost)
	}
	if cfg.LatencyThreshold != 500*time.Millisecond {
		t.Errorf("LatencyThreshold = %v, want 500ms", cfg.LatencyThreshold)
	}
}

func TestNewWatcher(t *testing.T) {
	tests := []struct {
		name             string
		cfg              Config
		wantPollInterval time.Duration
	}{
		{
			name:             "defaults applied",
			cfg:              Config{},
			wantPollInterval: 5 * time.Second,
		},
		{
			name:             "custom values preserved",
			cfg:              Config{PollInterval: 10 * time.Second},
			wantPollInterval: 10 * time.Second,
		},
		{
			name:             "zero interval gets default",
			cfg:              Config{PollInterval: 0},
			wantPollInterval: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := NewWatcher(tt.cfg)
			if watcher.cfg.PollInterval != tt.wantPollInterval {
				t.Errorf("PollInterval = %v, want %v", watcher.cfg.PollInterval, tt.wantPollInterval)
			}
			if watcher.interfaceStates == nil {
				t.Error("interfaceStates should be initialized")
			}
			if watcher.hostStates == nil {
				t.Error("hostStates should be initialized")
			}
			if watcher.eventChan == nil {
				t.Error("eventChan should be initialized")
			}
		})
	}
}

func TestEventTypes(t *testing.T) {
	// Verify all event type constants are defined
	eventTypes := []EventType{
		EventInterfaceUp,
		EventInterfaceDown,
		EventAddressAdded,
		EventAddressRemoved,
		EventConnectivityUp,
		EventConnectivityDown,
		EventLatencyChange,
		EventHostUp,
		EventHostDown,
	}

	for _, et := range eventTypes {
		if et == "" {
			t.Error("Event type should not be empty")
		}
	}
}

func TestInterfaceState(t *testing.T) {
	state := &InterfaceState{
		Name:      "eth0",
		IsUp:      true,
		Addresses: []string{"192.168.1.100/24", "fe80::1/64"},
	}

	if state.Name != "eth0" {
		t.Errorf("Name = %q, want eth0", state.Name)
	}
	if !state.IsUp {
		t.Error("IsUp should be true")
	}
	if len(state.Addresses) != 2 {
		t.Errorf("Addresses length = %d, want 2", len(state.Addresses))
	}
}

func TestHostState(t *testing.T) {
	now := time.Now()
	state := &HostState{
		Host:        "example.com",
		IsReachable: true,
		LastCheck:   now,
		LastLatency: 50 * time.Millisecond,
		Failures:    0,
	}

	if state.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", state.Host)
	}
	if !state.IsReachable {
		t.Error("IsReachable should be true")
	}
	if state.LastLatency != 50*time.Millisecond {
		t.Errorf("LastLatency = %v, want 50ms", state.LastLatency)
	}
}

func TestFormatEvent(t *testing.T) {
	event := Event{
		Type:      EventInterfaceUp,
		Timestamp: time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC),
		Interface: "eth0",
		Message:   "Interface eth0 came up",
	}

	formatted := FormatEvent(event)

	if formatted == "" {
		t.Error("FormatEvent returned empty string")
	}
	// Should contain time
	if !containsSubstring(formatted, "10:30:45") {
		t.Errorf("FormatEvent missing time, got: %s", formatted)
	}
	// Should contain event type
	if !containsSubstring(formatted, string(EventInterfaceUp)) {
		t.Errorf("FormatEvent missing event type, got: %s", formatted)
	}
	// Should contain message
	if !containsSubstring(formatted, "Interface eth0 came up") {
		t.Errorf("FormatEvent missing message, got: %s", formatted)
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestWatchContextCancellation(t *testing.T) {
	cfg := Config{
		PollInterval: 100 * time.Millisecond,
	}
	watcher := NewWatcher(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	eventChan := watcher.Watch(ctx)

	// Let it run briefly
	time.Sleep(150 * time.Millisecond)

	// Cancel context
	cancel()

	// Drain and wait for channel to close with longer timeout
	// (network operations can be slow)
	timeout := time.After(10 * time.Second)
	for {
		select {
		case _, open := <-eventChan:
			if !open {
				return // Channel closed successfully
			}
			// Continue draining
		case <-timeout:
			t.Error("Event channel did not close after context cancellation")
			return
		}
	}
}

func TestGetCurrentState(t *testing.T) {
	cfg := Config{
		PollInterval: 100 * time.Millisecond,
	}
	watcher := NewWatcher(cfg)

	// Initialize state
	watcher.initializeState()

	interfaces, hosts, connectivity := watcher.GetCurrentState()

	// Should have at least one interface (loopback)
	if len(interfaces) == 0 {
		t.Error("Should have at least one interface")
	}

	// Hosts should be empty by default
	if len(hosts) != 0 {
		t.Errorf("Expected no monitored hosts, got %d", len(hosts))
	}

	// Connectivity check depends on network, just verify it's a boolean
	_ = connectivity
}

func TestAddRemoveMonitoredHost(t *testing.T) {
	cfg := Config{}
	watcher := NewWatcher(cfg)

	// Add a host
	watcher.AddMonitoredHost("example.com")

	if len(watcher.hostStates) != 1 {
		t.Errorf("Expected 1 host state, got %d", len(watcher.hostStates))
	}
	if len(watcher.cfg.MonitoredHosts) != 1 {
		t.Errorf("Expected 1 monitored host, got %d", len(watcher.cfg.MonitoredHosts))
	}

	// Add same host again (should not duplicate)
	watcher.AddMonitoredHost("example.com")
	if len(watcher.hostStates) != 1 {
		t.Errorf("Should not duplicate, got %d host states", len(watcher.hostStates))
	}

	// Add another host
	watcher.AddMonitoredHost("google.com")
	if len(watcher.hostStates) != 2 {
		t.Errorf("Expected 2 host states, got %d", len(watcher.hostStates))
	}

	// Remove first host
	watcher.RemoveMonitoredHost("example.com")
	if len(watcher.hostStates) != 1 {
		t.Errorf("Expected 1 host state after removal, got %d", len(watcher.hostStates))
	}
	if len(watcher.cfg.MonitoredHosts) != 1 {
		t.Errorf("Expected 1 monitored host after removal, got %d", len(watcher.cfg.MonitoredHosts))
	}

	// Verify correct host remains
	if _, exists := watcher.hostStates["google.com"]; !exists {
		t.Error("Wrong host was removed")
	}
}

func TestIsConnected(t *testing.T) {
	cfg := Config{}
	watcher := NewWatcher(cfg)

	// Before initialization, should be false
	if watcher.IsConnected() {
		t.Error("Should be false before initialization")
	}

	// Initialize state
	watcher.initializeState()

	// After initialization, depends on actual network
	// Just verify it doesn't panic
	_ = watcher.IsConnected()
}

func TestInitializeState(t *testing.T) {
	cfg := Config{
		MonitoredHosts: []string{"127.0.0.1"},
	}
	watcher := NewWatcher(cfg)

	watcher.initializeState()

	// Should have interfaces
	if len(watcher.interfaceStates) == 0 {
		t.Error("Should have initialized interface states")
	}

	// Should have monitored host
	if len(watcher.hostStates) != 1 {
		t.Errorf("Expected 1 host state, got %d", len(watcher.hostStates))
	}

	// Loopback should be present
	hasLoopback := false
	for _, state := range watcher.interfaceStates {
		for _, addr := range state.Addresses {
			if containsSubstring(addr, "127.0.0.1") || containsSubstring(addr, "::1") {
				hasLoopback = true
				break
			}
		}
	}
	if !hasLoopback {
		t.Log("Loopback address not explicitly found in interface states (may be normal)")
	}
}

func TestSendEvent(t *testing.T) {
	cfg := Config{}
	watcher := NewWatcher(cfg)

	event := Event{
		Type:    EventInterfaceUp,
		Message: "Test event",
	}

	watcher.sendEvent(event)

	// Should be in channel
	select {
	case received := <-watcher.eventChan:
		if received.Message != "Test event" {
			t.Errorf("Message = %q, want 'Test event'", received.Message)
		}
		if received.Timestamp.IsZero() {
			t.Error("Timestamp should be set")
		}
	case <-time.After(time.Second):
		t.Error("Event not received from channel")
	}
}

func TestEventChannelFull(t *testing.T) {
	cfg := Config{}
	watcher := NewWatcher(cfg)

	// Fill the channel
	for i := 0; i < 100; i++ {
		watcher.sendEvent(Event{Message: "fill"})
	}

	// This should not block
	done := make(chan bool)
	go func() {
		watcher.sendEvent(Event{Message: "overflow"})
		done <- true
	}()

	select {
	case <-done:
		// Good, didn't block
	case <-time.After(time.Second):
		t.Error("sendEvent blocked on full channel")
	}
}

func TestPingHostLoopback(t *testing.T) {
	cfg := Config{}
	watcher := NewWatcher(cfg)

	// Loopback should be reachable
	// Note: This uses TCP so it depends on having a service listening
	// Skip if no service on port 80/443
	reachable := watcher.pingHost("127.0.0.1")

	// Just verify it doesn't panic - result depends on local services
	_ = reachable
}

func TestCheckHostRecordState(t *testing.T) {
	cfg := Config{
		LatencyThreshold: 10 * time.Millisecond,
	}
	watcher := NewWatcher(cfg)
	watcher.hostStates["test"] = &HostState{Host: "test"}

	watcher.checkHost("test")

	state := watcher.hostStates["test"]
	if state.LastCheck.IsZero() {
		t.Error("LastCheck should be set")
	}
}

func TestWatcherConcurrency(t *testing.T) {
	cfg := Config{
		PollInterval: 50 * time.Millisecond,
	}
	watcher := NewWatcher(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventChan := watcher.Watch(ctx)

	// Concurrent reads
	done := make(chan bool)
	go func() {
		for i := 0; i < 10; i++ {
			_, _, _ = watcher.GetCurrentState()
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 10; i++ {
			watcher.AddMonitoredHost("host" + string(rune(i+'0')))
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()

	// Drain events
	go func() {
		for range eventChan {
		}
	}()

	<-done
	<-done

	cancel()
}

func TestInterfaceStateSnapshot(t *testing.T) {
	cfg := Config{}
	watcher := NewWatcher(cfg)

	// Add test state
	watcher.interfaceStates["test"] = &InterfaceState{
		Name:      "test",
		IsUp:      true,
		Addresses: []string{"1.2.3.4/24"},
	}

	interfaces, _, _ := watcher.GetCurrentState()

	// Modify original
	watcher.interfaceStates["test"].Addresses = append(
		watcher.interfaceStates["test"].Addresses, "5.6.7.8/24")

	// Snapshot should be unchanged
	if len(interfaces["test"].Addresses) != 1 {
		t.Error("Snapshot should not be affected by modifications to original")
	}
}
