// Package upnp provides UPnP device discovery and service enumeration.
package upnp

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SSDPMulticastAddr = "239.255.255.250:1900"
	DefaultTimeout    = 3 * time.Second
)

// Device represents a discovered UPnP device.
type Device struct {
	IP           string
	Location     string
	Server       string
	USN          string
	ST           string
	FriendlyName string
	Manufacturer string
	ModelName    string
	ModelNumber  string
	DeviceType   string
	Services     []Service
	ResponseTime time.Duration
	RawHeaders   map[string]string
}

// Service represents a UPnP service.
type Service struct {
	ServiceType string
	ServiceID   string
	ControlURL  string
	EventSubURL string
	SCPDURL     string
}

// DeviceDescription represents the XML device description.
type DeviceDescription struct {
	XMLName xml.Name   `xml:"root"`
	Device  DeviceInfo `xml:"device"`
}

type DeviceInfo struct {
	DeviceType       string       `xml:"deviceType"`
	FriendlyName     string       `xml:"friendlyName"`
	Manufacturer     string       `xml:"manufacturer"`
	ManufacturerURL  string       `xml:"manufacturerURL"`
	ModelDescription string       `xml:"modelDescription"`
	ModelName        string       `xml:"modelName"`
	ModelNumber      string       `xml:"modelNumber"`
	ModelURL         string       `xml:"modelURL"`
	SerialNumber     string       `xml:"serialNumber"`
	UDN              string       `xml:"UDN"`
	ServiceList      ServiceList  `xml:"serviceList"`
	DeviceList       []DeviceInfo `xml:"deviceList>device"`
}

type ServiceList struct {
	Services []ServiceInfo `xml:"service"`
}

type ServiceInfo struct {
	ServiceType string `xml:"serviceType"`
	ServiceID   string `xml:"serviceId"`
	ControlURL  string `xml:"controlURL"`
	EventSubURL string `xml:"eventSubURL"`
	SCPDURL     string `xml:"SCPDURL"`
}

// ScanResult contains UPnP scan results.
type ScanResult struct {
	Devices       []Device
	TotalFound    int
	UniqueDevices int
	StartTime     time.Time
	Duration      time.Duration
}

// Config holds scanner configuration.
type Config struct {
	Timeout      time.Duration
	SearchTarget string
	FetchDetails bool
	HTTPTimeout  time.Duration
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:      3 * time.Second,
		SearchTarget: "ssdp:all",
		FetchDetails: true,
		HTTPTimeout:  5 * time.Second,
	}
}

// Scanner performs UPnP discovery.
type Scanner struct {
	config Config
	client *http.Client
}

// New creates a new UPnP scanner.
func New(cfg Config) *Scanner {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.SearchTarget == "" {
		cfg.SearchTarget = "ssdp:all"
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}

	return &Scanner{
		config: cfg,
		client: &http.Client{Timeout: cfg.HTTPTimeout},
	}
}

// Scan performs UPnP device discovery.
func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	result := &ScanResult{StartTime: time.Now()}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(s.config.Timeout))

	// Send M-SEARCH
	request := s.buildMSearch()
	addr, _ := net.ResolveUDPAddr("udp4", SSDPMulticastAddr)
	startTime := time.Now()
	conn.WriteToUDP([]byte(request), addr)

	// Collect responses
	seen := make(map[string]bool)
	buf := make([]byte, 4096)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		device := s.parseResponse(buf[:n], remoteAddr.IP.String())
		device.ResponseTime = time.Since(startTime)

		key := device.USN
		if key == "" {
			key = device.Location
		}

		if key != "" && !seen[key] {
			seen[key] = true
			result.Devices = append(result.Devices, device)
		}
	}

	result.TotalFound = len(result.Devices)
	result.UniqueDevices = len(seen)
	result.Duration = time.Since(result.StartTime)

	// Fetch device details if enabled
	if s.config.FetchDetails {
		s.fetchAllDetails(ctx, result)
	}

	// Sort by IP
	sort.Slice(result.Devices, func(i, j int) bool {
		return result.Devices[i].IP < result.Devices[j].IP
	})

	return result, nil
}

func (s *Scanner) buildMSearch() string {
	return fmt.Sprintf(
		"M-SEARCH * HTTP/1.1\r\n"+
			"HOST: %s\r\n"+
			"MAN: \"ssdp:discover\"\r\n"+
			"MX: 2\r\n"+
			"ST: %s\r\n"+
			"\r\n",
		SSDPMulticastAddr,
		s.config.SearchTarget,
	)
}

func (s *Scanner) parseResponse(data []byte, ip string) Device {
	device := Device{
		IP:         ip,
		RawHeaders: make(map[string]string),
	}

	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			device.RawHeaders[key] = value

			switch strings.ToLower(key) {
			case "location":
				device.Location = value
			case "server":
				device.Server = value
			case "usn":
				device.USN = value
			case "st":
				device.ST = value
			}
		}
	}

	return device
}

func (s *Scanner) fetchAllDetails(ctx context.Context, result *ScanResult) {
	var wg sync.WaitGroup

	for i := range result.Devices {
		if result.Devices[i].Location == "" {
			continue
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s.fetchDeviceDetails(ctx, &result.Devices[idx])
		}(i)
	}

	wg.Wait()
}

func (s *Scanner) fetchDeviceDetails(ctx context.Context, device *Device) {
	req, err := http.NewRequestWithContext(ctx, "GET", device.Location, nil)
	if err != nil {
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return
	}

	var desc DeviceDescription
	if err := xml.Unmarshal(body, &desc); err != nil {
		return
	}

	device.FriendlyName = desc.Device.FriendlyName
	device.Manufacturer = desc.Device.Manufacturer
	device.ModelName = desc.Device.ModelName
	device.ModelNumber = desc.Device.ModelNumber
	device.DeviceType = desc.Device.DeviceType

	for _, svc := range desc.Device.ServiceList.Services {
		device.Services = append(device.Services, Service{
			ServiceType: svc.ServiceType,
			ServiceID:   svc.ServiceID,
			ControlURL:  svc.ControlURL,
			EventSubURL: svc.EventSubURL,
			SCPDURL:     svc.SCPDURL,
		})
	}
}

// FetchDetails fetches details for a single device.
func (s *Scanner) FetchDetails(ctx context.Context, device *Device) error {
	if device.Location == "" {
		return fmt.Errorf("device has no location URL")
	}
	s.fetchDeviceDetails(ctx, device)
	return nil
}

// Format returns formatted scan results.
func (r *ScanResult) Format() string {
	var sb strings.Builder

	sb.WriteString("UPnP Device Discovery Results\n")
	sb.WriteString(strings.Repeat("─", 70) + "\n\n")

	if len(r.Devices) == 0 {
		sb.WriteString("No UPnP devices found.\n")
	} else {
		for _, d := range r.Devices {
			name := d.FriendlyName
			if name == "" {
				name = d.Server
			}
			if name == "" {
				name = "Unknown Device"
			}

			sb.WriteString(fmt.Sprintf("📱 %s\n", name))
			sb.WriteString(fmt.Sprintf("   IP:       %s\n", d.IP))

			if d.Manufacturer != "" {
				sb.WriteString(fmt.Sprintf("   Maker:    %s\n", d.Manufacturer))
			}
			if d.ModelName != "" {
				sb.WriteString(fmt.Sprintf("   Model:    %s", d.ModelName))
				if d.ModelNumber != "" {
					sb.WriteString(fmt.Sprintf(" (%s)", d.ModelNumber))
				}
				sb.WriteString("\n")
			}
			if d.DeviceType != "" {
				sb.WriteString(fmt.Sprintf("   Type:     %s\n", formatDeviceType(d.DeviceType)))
			}
			if len(d.Services) > 0 {
				sb.WriteString(fmt.Sprintf("   Services: %d\n", len(d.Services)))
			}
			sb.WriteString(fmt.Sprintf("   Response: %v\n", d.ResponseTime.Round(time.Millisecond)))
			sb.WriteString("\n")
		}
	}

	sb.WriteString(strings.Repeat("─", 70) + "\n")
	sb.WriteString(fmt.Sprintf("Found: %d devices | Duration: %v\n",
		r.UniqueDevices, r.Duration.Round(time.Millisecond)))

	return sb.String()
}

func formatDeviceType(dt string) string {
	// Extract the device type name from URN
	parts := strings.Split(dt, ":")
	if len(parts) >= 4 {
		return parts[3]
	}
	return dt
}

// CommonSearchTargets returns common UPnP search targets.
func CommonSearchTargets() []string {
	return []string{
		"ssdp:all",
		"upnp:rootdevice",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:device:MediaServer:1",
		"urn:schemas-upnp-org:device:MediaRenderer:1",
	}
}
