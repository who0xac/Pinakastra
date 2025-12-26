package intelligence

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SubdomainIntelligence contains all intelligence data for a single subdomain
type SubdomainIntelligence struct {
	Subdomain    string
	StatusCode   int
	ResponseTime time.Duration
	IPs          []string
	Location     string // City, Country
	ASN          string
	ASNDesc      string
	Country      string
	HTTPTitle    string
	HTTPSize     string
	TechStack    []string
	SecurityHeaders struct {
		Present []string
		Missing []string
		WAF     string
		TLS     string
	}
	OpenPorts    []int
	Cloud        string
	TLSAltNames  []string
	Endpoints    struct {
		Admin []EndpointInfo
		API   []EndpointInfo
		Files []string
	}
	Vulnerabilities []VulnerabilityInfo
	CVEs            []CVEInfo
}

// EndpointInfo contains information about discovered endpoints
type EndpointInfo struct {
	Path   string
	Status string // "protected", "open", "forbidden", etc.
}

// VulnerabilityInfo contains vulnerability details with endpoints
type VulnerabilityInfo struct {
	Type      string
	Severity  string // CRITICAL, HIGH, MEDIUM, LOW
	Endpoint  string
	Parameter string
	Details   string
}

// CVEInfo contains verified CVE information
type CVEInfo struct {
	ID             string
	Description    string
	Severity       string
	Score          float64
	Service        string
	Version        string
	Verified       bool
	Exploitable    bool
	ExploitDetails string
	PublishedDate  string
	LastModified   string
}

// Aggregator collects intelligence data from all scan phases
type Aggregator struct {
	subdomains map[string]*SubdomainIntelligence
}

// NewAggregator creates a new intelligence aggregator
func NewAggregator() *Aggregator {
	return &Aggregator{
		subdomains: make(map[string]*SubdomainIntelligence),
	}
}

// AddSubdomain initializes a subdomain entry
func (a *Aggregator) AddSubdomain(subdomain string) {
	if _, exists := a.subdomains[subdomain]; !exists {
		a.subdomains[subdomain] = &SubdomainIntelligence{
			Subdomain: subdomain,
		}
	}
}

// SetHTTPInfo sets HTTP probe information
func (a *Aggregator) SetHTTPInfo(subdomain string, statusCode int, responseTime time.Duration, title, size string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]
	intel.StatusCode = statusCode
	intel.ResponseTime = responseTime
	intel.HTTPTitle = title
	intel.HTTPSize = size
}

// AddIP adds an IP address to subdomain
func (a *Aggregator) AddIP(subdomain string, ip string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]

	// Check if IP already exists
	for _, existingIP := range intel.IPs {
		if existingIP == ip {
			return
		}
	}

	intel.IPs = append(intel.IPs, ip)
}

// SetLocation sets geolocation information
func (a *Aggregator) SetLocation(subdomain, location string) {
	a.AddSubdomain(subdomain)
	a.subdomains[subdomain].Location = location
}

// SetASN sets ASN information
func (a *Aggregator) SetASN(subdomain, asn, desc, country string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]
	intel.ASN = asn
	intel.ASNDesc = desc
	intel.Country = country
}

// AddTechnology adds a detected technology
func (a *Aggregator) AddTechnology(subdomain, tech string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]

	// Check if tech already exists
	for _, existingTech := range intel.TechStack {
		if existingTech == tech {
			return
		}
	}

	intel.TechStack = append(intel.TechStack, tech)
}

// SetSecurityHeaders sets security header information
func (a *Aggregator) SetSecurityHeaders(subdomain string, present, missing []string, waf, tls string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]
	intel.SecurityHeaders.Present = present
	intel.SecurityHeaders.Missing = missing
	intel.SecurityHeaders.WAF = waf
	intel.SecurityHeaders.TLS = tls
}

// AddPort adds an open port
func (a *Aggregator) AddPort(subdomain string, port int) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]

	// Check if port already exists
	for _, existingPort := range intel.OpenPorts {
		if existingPort == port {
			return
		}
	}

	intel.OpenPorts = append(intel.OpenPorts, port)
	sort.Ints(intel.OpenPorts)
}

// SetCloud sets cloud provider information
func (a *Aggregator) SetCloud(subdomain, cloud string) {
	a.AddSubdomain(subdomain)
	a.subdomains[subdomain].Cloud = cloud
}

// AddTLSAltName adds TLS alternative name
func (a *Aggregator) AddTLSAltName(subdomain, altName string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]

	// Check if already exists
	for _, existing := range intel.TLSAltNames {
		if existing == altName {
			return
		}
	}

	intel.TLSAltNames = append(intel.TLSAltNames, altName)
}

// AddAdminEndpoint adds an admin panel endpoint
func (a *Aggregator) AddAdminEndpoint(subdomain, path, status string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]
	intel.Endpoints.Admin = append(intel.Endpoints.Admin, EndpointInfo{
		Path:   path,
		Status: status,
	})
}

// AddAPIEndpoint adds an API endpoint
func (a *Aggregator) AddAPIEndpoint(subdomain, path, status string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]
	intel.Endpoints.API = append(intel.Endpoints.API, EndpointInfo{
		Path:   path,
		Status: status,
	})
}

// AddFile adds a discovered file
func (a *Aggregator) AddFile(subdomain, file string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]
	intel.Endpoints.Files = append(intel.Endpoints.Files, file)
}

// AddVulnerability adds a vulnerability with endpoint information
func (a *Aggregator) AddVulnerability(subdomain, vulnType, severity, endpoint, parameter, details string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]
	intel.Vulnerabilities = append(intel.Vulnerabilities, VulnerabilityInfo{
		Type:      vulnType,
		Severity:  severity,
		Endpoint:  endpoint,
		Parameter: parameter,
		Details:   details,
	})
}

// AddCVE adds a verified CVE
func (a *Aggregator) AddCVE(subdomain, cveID, severity string, score float64, service, version string, verified, exploitable bool, exploitDetails string) {
	a.AddSubdomain(subdomain)
	intel := a.subdomains[subdomain]
	intel.CVEs = append(intel.CVEs, CVEInfo{
		ID:             cveID,
		Severity:       severity,
		Score:          score,
		Service:        service,
		Version:        version,
		Verified:       verified,
		Exploitable:    exploitable,
		ExploitDetails: exploitDetails,
	})
}

// GetIntelligence returns intelligence for a specific subdomain
func (a *Aggregator) GetIntelligence(subdomain string) *SubdomainIntelligence {
	return a.subdomains[subdomain]
}

// GetAllIntelligence returns all collected intelligence sorted by subdomain
func (a *Aggregator) GetAllIntelligence() []*SubdomainIntelligence {
	var results []*SubdomainIntelligence

	for _, intel := range a.subdomains {
		results = append(results, intel)
	}

	// Sort by subdomain name
	sort.Slice(results, func(i, j int) bool {
		return results[i].Subdomain < results[j].Subdomain
	})

	return results
}

// GetStatistics returns summary statistics
func (a *Aggregator) GetStatistics() map[string]interface{} {
	stats := make(map[string]interface{})

	totalSubdomains := len(a.subdomains)
	totalVulns := 0
	totalCVEs := 0
	criticalVulns := 0
	highVulns := 0
	exploitableCVEs := 0

	for _, intel := range a.subdomains {
		totalVulns += len(intel.Vulnerabilities)
		totalCVEs += len(intel.CVEs)

		for _, vuln := range intel.Vulnerabilities {
			if vuln.Severity == "CRITICAL" {
				criticalVulns++
			} else if vuln.Severity == "HIGH" {
				highVulns++
			}
		}

		for _, cve := range intel.CVEs {
			if cve.Exploitable {
				exploitableCVEs++
			}
		}
	}

	stats["total_subdomains"] = totalSubdomains
	stats["total_vulnerabilities"] = totalVulns
	stats["total_cves"] = totalCVEs
	stats["critical_vulnerabilities"] = criticalVulns
	stats["high_vulnerabilities"] = highVulns
	stats["exploitable_cves"] = exploitableCVEs

	return stats
}

// FormatPortList formats port list for display
func FormatPortList(ports []int) string {
	if len(ports) == 0 {
		return "None"
	}

	var portStrs []string
	for _, port := range ports {
		portStrs = append(portStrs, fmt.Sprintf("%d", port))
	}

	if len(portStrs) > 5 {
		return fmt.Sprintf("%s +%d more", strings.Join(portStrs[:5], ", "), len(portStrs)-5)
	}

	return strings.Join(portStrs, ", ")
}

// FormatIPList formats IP list for display
func FormatIPList(ips []string) string {
	if len(ips) == 0 {
		return "None"
	}

	if len(ips) > 3 {
		return fmt.Sprintf("%s +%d more", strings.Join(ips[:3], ", "), len(ips)-3)
	}

	return strings.Join(ips, ", ")
}

// FormatEndpoints formats endpoint list for display
func FormatEndpoints(endpoints []EndpointInfo, maxShow int) string {
	if len(endpoints) == 0 {
		return ""
	}

	var parts []string
	limit := maxShow
	if len(endpoints) < limit {
		limit = len(endpoints)
	}

	for i := 0; i < limit; i++ {
		parts = append(parts, fmt.Sprintf("%s (%s)", endpoints[i].Path, endpoints[i].Status))
	}

	result := strings.Join(parts, ", ")
	if len(endpoints) > maxShow {
		result += fmt.Sprintf(" +%d more", len(endpoints)-maxShow)
	}

	return result
}
