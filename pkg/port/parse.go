package port

import (
	"encoding/xml"
	"os"
	"strconv"
)

// NmapRun represents the root of Nmap XML output
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a scanned host
type Host struct {
	Address  []Address `xml:"address"`
	Ports    Ports     `xml:"ports"`
	HostName HostName  `xml:"hostnames>hostname"`
	OS       OS        `xml:"os"`
}

// Address represents an IP/MAC address
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// Ports contains port information
type Ports struct {
	Port []Port `xml:"port"`
}

// Port represents a single port
type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   string  `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
	Script   []Script `xml:"script"`
}

// State represents port state
type State struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Service represents service detection
type Service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	CPE       []CPE  `xml:"cpe"`
}

// CPE represents Common Platform Enumeration
type CPE struct {
	Value string `xml:",chardata"`
}

// Script represents Nmap script output
type Script struct {
	ID     string  `xml:"id,attr"`
	Output string  `xml:"output,attr"`
	Table  []Table `xml:"table"`
	Elem   []Elem  `xml:"elem"`
}

// Table represents script table output
type Table struct {
	Key  string `xml:"key,attr"`
	Elem []Elem `xml:"elem"`
}

// Elem represents script element
type Elem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// HostName represents hostname information
type HostName struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// OS represents operating system detection
type OS struct {
	OSMatches []OSMatch `xml:"osmatch"`
}

// OSMatch represents an OS match
type OSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// parseNmapXML parses Nmap XML output and extracts service and host information
func parseNmapXML(filename string) ([]ServiceInfo, []HostInfo, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		return nil, nil, err
	}

	var services []ServiceInfo
	var hosts []HostInfo

	for _, host := range nmapRun.Hosts {
		// Get IP address
		var ipAddr string
		for _, addr := range host.Address {
			if addr.AddrType == "ipv4" {
				ipAddr = addr.Addr
				break
			}
		}

		if ipAddr == "" {
			continue
		}

		// Get OS detection info
		var osName string
		var osAccuracy string
		if len(host.OS.OSMatches) > 0 {
			osName = host.OS.OSMatches[0].Name
			osAccuracy = host.OS.OSMatches[0].Accuracy
		}

		// Create host info
		hostInfo := HostInfo{
			IP:       ipAddr,
			OS:       osName,
			Accuracy: osAccuracy,
			Services: []ServiceInfo{},
		}

		// Process each port
		for _, port := range host.Ports.Port {
			if port.State.State != "open" {
				continue
			}

			portNum, _ := strconv.Atoi(port.PortID)

			svc := ServiceInfo{
				IP:        ipAddr,
				Port:      portNum,
				Protocol:  port.Protocol,
				State:     port.State.State,
				Service:   port.Service.Name,
				Version:   port.Service.Version,
				Product:   port.Service.Product,
				ExtraInfo: port.Service.ExtraInfo,
				CVEs:      []string{},
			}

			// Extract CVEs from vulnerability scripts
			for _, script := range port.Script {
				if script.ID == "vulners" || script.ID == "vulscan" {
					cves := extractCVEsFromScript(script)
					svc.CVEs = append(svc.CVEs, cves...)
				}
			}

			services = append(services, svc)
			hostInfo.Services = append(hostInfo.Services, svc)
		}

		hosts = append(hosts, hostInfo)
	}

	return services, hosts, nil
}

// extractCVEsFromScript extracts CVE IDs from Nmap script output
func extractCVEsFromScript(script Script) []string {
	var cves []string

	// Parse from script output
	if script.Output != "" {
		cves = append(cves, parseCVEsFromText(script.Output)...)
	}

	// Parse from table elements
	for _, table := range script.Table {
		for _, elem := range table.Elem {
			if elem.Key == "id" || elem.Key == "cveid" {
				if isCVE(elem.Value) {
					cves = append(cves, elem.Value)
				}
			}
		}
	}

	// Parse from direct elements
	for _, elem := range script.Elem {
		if elem.Key == "id" || elem.Key == "cveid" {
			if isCVE(elem.Value) {
				cves = append(cves, elem.Value)
			}
		}
	}

	return cves
}

// parseCVEsFromText extracts CVE IDs from text using regex pattern
func parseCVEsFromText(text string) []string {
	var cves []string
	// Simple CVE pattern matching
	// CVE format: CVE-YYYY-NNNN (e.g., CVE-2021-44228)
	words := splitOnNonAlphanumeric(text)
	for _, word := range words {
		if isCVE(word) {
			cves = append(cves, word)
		}
	}
	return cves
}

// isCVE checks if string matches CVE pattern
func isCVE(s string) bool {
	if len(s) < 13 {
		return false
	}
	return s[:4] == "CVE-" && s[4] >= '1' && s[4] <= '9'
}

// splitOnNonAlphanumeric splits string on non-alphanumeric characters
func splitOnNonAlphanumeric(s string) []string {
	var words []string
	var current []rune

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			current = append(current, r)
		} else {
			if len(current) > 0 {
				words = append(words, string(current))
				current = nil
			}
		}
	}

	if len(current) > 0 {
		words = append(words, string(current))
	}

	return words
}
