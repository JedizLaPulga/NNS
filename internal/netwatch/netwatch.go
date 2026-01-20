// Package netwatch provides network monitoring and change detection.
package netwatch

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// EventType represents the type of network change.
type EventType string

const (
	EventInterfaceUp      EventType = "interface_up"
	EventInterfaceDown    EventType = "interface_down"
	EventAddressAdded     EventType = "address_added"
	EventAddressRemoved   EventType = "address_removed"
	EventConnectivityUp   EventType = "connectivity_up"
	EventConnectivityDown EventType = "connectivity_down"
	EventLatencyChange    EventType = "latency_change"
	EventHostUp           EventType = "host_up"
	EventHostDown         EventType = "host_down"
)

// Event represents a network change event.
type Event struct {
	Type      EventType     `json:"type"`
	Timestamp time.Time     `json:"timestamp"`
	Interface string        `json:"interface,omitempty"`
	Address   string        `json:"address,omitempty"`
	OldValue  string        `json:"old_value,omitempty"`
	NewValue  string        `json:"new_value,omitempty"`
	Host      string        `json:"host,omitempty"`
	Latency   time.Duration `json:"latency,omitempty"`
	Message   string        `json:"message"`
}

// InterfaceState holds the current state of an interface.
type InterfaceState struct {
	Name      string
	IsUp      bool
	Addresses []string // IP addresses (CIDR notation)
}

// HostState represents monitored host status.
type HostState struct {
	Host        string
	IsReachable bool
	LastCheck   time.Time
	LastLatency time.Duration
	Failures    int
}

// Config configures the network watcher.
type Config struct {
	PollInterval          time.Duration // How often to check for changes
	ConnectivityCheckHost string        // Host to ping for connectivity check
	MonitoredHosts        []string      // Additional hosts to monitor
	LatencyThreshold      time.Duration // Alert if latency exceeds this
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		PollInterval:          5 * time.Second,
		ConnectivityCheckHost: "8.8.8.8",
		MonitoredHosts:        []string{},
		LatencyThreshold:      500 * time.Millisecond,
	}
}

// Watcher monitors network changes.
type Watcher struct {
	cfg             Config
	interfaceStates map[string]*InterfaceState
	hostStates      map[string]*HostState
	hasConnectivity bool
	mu              sync.RWMutex
	eventChan       chan Event
}

// NewWatcher creates a new network watcher.
func NewWatcher(cfg Config) *Watcher {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.ConnectivityCheckHost == "" {
		cfg.ConnectivityCheckHost = "8.8.8.8"
	}

	return &Watcher{
		cfg:             cfg,
		interfaceStates: make(map[string]*InterfaceState),
		hostStates:      make(map[string]*HostState),
		eventChan:       make(chan Event, 100),
	}
}

// Watch starts watching for network changes.
// Events are sent through the returned channel.
// Cancel the context to stop watching.
func (w *Watcher) Watch(ctx context.Context) <-chan Event {
	// Initialize state
	w.initializeState()

	go func() {
		ticker := time.NewTicker(w.cfg.PollInterval)
		defer ticker.Stop()
		defer close(w.eventChan)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.checkForChanges()
			}
		}
	}()

	return w.eventChan
}

func (w *Watcher) initializeState() {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Get initial interface states
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			state := &InterfaceState{
				Name:      iface.Name,
				IsUp:      iface.Flags&net.FlagUp != 0,
				Addresses: make([]string, 0),
			}

			addrs, err := iface.Addrs()
			if err == nil {
				for _, addr := range addrs {
					state.Addresses = append(state.Addresses, addr.String())
				}
			}

			w.interfaceStates[iface.Name] = state
		}
	}

	// Check initial connectivity
	w.hasConnectivity = w.checkConnectivity()

	// Initialize monitored hosts
	for _, host := range w.cfg.MonitoredHosts {
		w.hostStates[host] = &HostState{
			Host:        host,
			IsReachable: w.pingHost(host),
			LastCheck:   time.Now(),
		}
	}
}

func (w *Watcher) checkForChanges() {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	currentIfaces := make(map[string]bool)

	for _, iface := range ifaces {
		currentIfaces[iface.Name] = true
		isUp := iface.Flags&net.FlagUp != 0

		state, exists := w.interfaceStates[iface.Name]
		if !exists {
			// New interface
			state = &InterfaceState{
				Name:      iface.Name,
				IsUp:      isUp,
				Addresses: make([]string, 0),
			}
			w.interfaceStates[iface.Name] = state

			if isUp {
				w.sendEvent(Event{
					Type:      EventInterfaceUp,
					Interface: iface.Name,
					Message:   fmt.Sprintf("Interface %s came up", iface.Name),
				})
			}
		} else {
			// Check if up/down status changed
			if state.IsUp != isUp {
				state.IsUp = isUp
				if isUp {
					w.sendEvent(Event{
						Type:      EventInterfaceUp,
						Interface: iface.Name,
						Message:   fmt.Sprintf("Interface %s came up", iface.Name),
					})
				} else {
					w.sendEvent(Event{
						Type:      EventInterfaceDown,
						Interface: iface.Name,
						Message:   fmt.Sprintf("Interface %s went down", iface.Name),
					})
				}
			}
		}

		// Check addresses
		addrs, err := iface.Addrs()
		if err == nil {
			currentAddrs := make(map[string]bool)
			for _, addr := range addrs {
				addrStr := addr.String()
				currentAddrs[addrStr] = true

				// Check if this is a new address
				found := false
				for _, existing := range state.Addresses {
					if existing == addrStr {
						found = true
						break
					}
				}
				if !found {
					w.sendEvent(Event{
						Type:      EventAddressAdded,
						Interface: iface.Name,
						Address:   addrStr,
						Message:   fmt.Sprintf("Address %s added to %s", addrStr, iface.Name),
					})
				}
			}

			// Check for removed addresses
			for _, existing := range state.Addresses {
				if !currentAddrs[existing] {
					w.sendEvent(Event{
						Type:      EventAddressRemoved,
						Interface: iface.Name,
						Address:   existing,
						Message:   fmt.Sprintf("Address %s removed from %s", existing, iface.Name),
					})
				}
			}

			// Update addresses
			state.Addresses = make([]string, 0, len(addrs))
			for _, addr := range addrs {
				state.Addresses = append(state.Addresses, addr.String())
			}
		}
	}

	// Check for removed interfaces
	for name, state := range w.interfaceStates {
		if !currentIfaces[name] && state.IsUp {
			w.sendEvent(Event{
				Type:      EventInterfaceDown,
				Interface: name,
				Message:   fmt.Sprintf("Interface %s was removed", name),
			})
			delete(w.interfaceStates, name)
		}
	}

	// Check connectivity
	hasConn := w.checkConnectivity()
	if hasConn != w.hasConnectivity {
		w.hasConnectivity = hasConn
		if hasConn {
			w.sendEvent(Event{
				Type:    EventConnectivityUp,
				Host:    w.cfg.ConnectivityCheckHost,
				Message: "Internet connectivity restored",
			})
		} else {
			w.sendEvent(Event{
				Type:    EventConnectivityDown,
				Host:    w.cfg.ConnectivityCheckHost,
				Message: "Internet connectivity lost",
			})
		}
	}

	// Check monitored hosts
	for _, host := range w.cfg.MonitoredHosts {
		w.checkHost(host)
	}
}

func (w *Watcher) checkHost(host string) {
	state, exists := w.hostStates[host]
	if !exists {
		state = &HostState{Host: host}
		w.hostStates[host] = state
	}

	start := time.Now()
	reachable := w.pingHost(host)
	latency := time.Since(start)

	state.LastCheck = time.Now()
	state.LastLatency = latency

	if reachable != state.IsReachable {
		state.IsReachable = reachable
		if reachable {
			state.Failures = 0
			w.sendEvent(Event{
				Type:    EventHostUp,
				Host:    host,
				Latency: latency,
				Message: fmt.Sprintf("Host %s is now reachable", host),
			})
		} else {
			state.Failures++
			w.sendEvent(Event{
				Type:    EventHostDown,
				Host:    host,
				Message: fmt.Sprintf("Host %s is unreachable", host),
			})
		}
	}

	// Check latency threshold
	if reachable && latency > w.cfg.LatencyThreshold {
		w.sendEvent(Event{
			Type:    EventLatencyChange,
			Host:    host,
			Latency: latency,
			Message: fmt.Sprintf("High latency to %s: %v", host, latency),
		})
	}
}

func (w *Watcher) sendEvent(event Event) {
	event.Timestamp = time.Now()
	select {
	case w.eventChan <- event:
	default:
		// Channel full, drop event
	}
}

func (w *Watcher) checkConnectivity() bool {
	return w.pingHost(w.cfg.ConnectivityCheckHost)
}

func (w *Watcher) pingHost(host string) bool {
	// Use TCP connection as a simple reachability check
	// (ICMP requires elevated privileges)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), 2*time.Second)
	if err != nil {
		// Try HTTPS port
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 2*time.Second)
		if err != nil {
			return false
		}
	}
	conn.Close()
	return true
}

// GetCurrentState returns the current state snapshot.
func (w *Watcher) GetCurrentState() (interfaces map[string]*InterfaceState, hosts map[string]*HostState, connectivity bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	interfaces = make(map[string]*InterfaceState)
	for k, v := range w.interfaceStates {
		state := &InterfaceState{
			Name:      v.Name,
			IsUp:      v.IsUp,
			Addresses: make([]string, len(v.Addresses)),
		}
		copy(state.Addresses, v.Addresses)
		interfaces[k] = state
	}

	hosts = make(map[string]*HostState)
	for k, v := range w.hostStates {
		hosts[k] = &HostState{
			Host:        v.Host,
			IsReachable: v.IsReachable,
			LastCheck:   v.LastCheck,
			LastLatency: v.LastLatency,
			Failures:    v.Failures,
		}
	}

	return interfaces, hosts, w.hasConnectivity
}

// AddMonitoredHost adds a host to monitor.
func (w *Watcher) AddMonitoredHost(host string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.hostStates[host]; !exists {
		w.hostStates[host] = &HostState{
			Host:      host,
			LastCheck: time.Now(),
		}
		w.cfg.MonitoredHosts = append(w.cfg.MonitoredHosts, host)
	}
}

// RemoveMonitoredHost removes a host from monitoring.
func (w *Watcher) RemoveMonitoredHost(host string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.hostStates, host)

	newHosts := make([]string, 0, len(w.cfg.MonitoredHosts))
	for _, h := range w.cfg.MonitoredHosts {
		if h != host {
			newHosts = append(newHosts, h)
		}
	}
	w.cfg.MonitoredHosts = newHosts
}

// FormatEvent formats an event for display.
func FormatEvent(e Event) string {
	return fmt.Sprintf("[%s] %s: %s",
		e.Timestamp.Format("15:04:05"),
		e.Type,
		e.Message)
}

// IsConnected returns current connectivity status.
func (w *Watcher) IsConnected() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.hasConnectivity
}
