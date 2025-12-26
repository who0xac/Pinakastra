package intelligence

import (
	"fmt"
	"regexp"
	"strings"
)

// CVEVerifier handles CVE verification logic
type CVEVerifier struct {
	// Known CVE database with version ranges and exploitability info
	cveDatabase map[string]CVEDetails
}

// CVEDetails contains CVE metadata for verification
type CVEDetails struct {
	ID                string
	Service           string
	AffectedVersions  []string
	Severity          string
	Score             float64
	Exploitable       bool
	ExploitAvailable  bool
	ExploitDetails    string
	RequiresCondition string
}

// NewCVEVerifier creates a new CVE verifier with database
func NewCVEVerifier() *CVEVerifier {
	v := &CVEVerifier{
		cveDatabase: make(map[string]CVEDetails),
	}
	v.initializeDatabase()
	return v
}

// initializeDatabase initializes the CVE database with known CVEs
func (v *CVEVerifier) initializeDatabase() {
	// Sample CVE database - in production this would be loaded from external source
	cves := []CVEDetails{
		{
			ID:               "CVE-2021-44228",
			Service:          "log4j",
			AffectedVersions: []string{"2.0-beta9", "2.0-rc1", "2.0-rc2", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14", "2.15"},
			Severity:         "CRITICAL",
			Score:            10.0,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Remote Code Execution via JNDI injection",
		},
		{
			ID:               "CVE-2021-45046",
			Service:          "log4j",
			AffectedVersions: []string{"2.0-beta9", "2.0-rc1", "2.0-rc2", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14", "2.15"},
			Severity:         "HIGH",
			Score:            9.0,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "DoS and RCE in certain configurations",
		},
		{
			ID:               "CVE-2022-22965",
			Service:          "spring",
			AffectedVersions: []string{"5.3.0", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5", "5.3.6", "5.3.7", "5.3.8", "5.3.9", "5.3.10", "5.3.11", "5.3.12", "5.3.13", "5.3.14", "5.3.15", "5.3.16", "5.3.17"},
			Severity:         "CRITICAL",
			Score:            9.8,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Spring4Shell RCE vulnerability",
		},
		{
			ID:               "CVE-2017-5638",
			Service:          "struts",
			AffectedVersions: []string{"2.3.5", "2.3.6", "2.3.7", "2.3.8", "2.3.9", "2.3.10", "2.3.11", "2.3.12", "2.3.13", "2.3.14", "2.3.15", "2.3.16", "2.3.17", "2.3.18", "2.3.19", "2.3.20", "2.3.21", "2.3.22", "2.3.23", "2.3.24", "2.3.25", "2.3.26", "2.3.27", "2.3.28", "2.3.29", "2.3.30", "2.3.31"},
			Severity:         "CRITICAL",
			Score:            10.0,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Remote Code Execution via Content-Type header",
		},
		{
			ID:               "CVE-2019-10842",
			Service:          "cloudflare",
			AffectedVersions: []string{"*"},
			Severity:         "HIGH",
			Score:            10.0,
			Exploitable:      false,
			ExploitAvailable: false,
			ExploitDetails:   "Theoretical vulnerability, requires specific configuration",
		},
		{
			ID:               "CVE-2020-15236",
			Service:          "cloudflare",
			AffectedVersions: []string{"*"},
			Severity:         "HIGH",
			Score:            8.6,
			Exploitable:      false,
			ExploitAvailable: false,
			ExploitDetails:   "DoS under specific conditions",
		},
		{
			ID:               "CVE-2021-3761",
			Service:          "cloudflare",
			AffectedVersions: []string{"*"},
			Severity:         "HIGH",
			Score:            7.5,
			Exploitable:      false,
			ExploitAvailable: false,
			ExploitDetails:   "Information disclosure, mitigated by Cloudflare",
		},
		{
			ID:               "CVE-2014-0160",
			Service:          "openssl",
			AffectedVersions: []string{"1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"},
			Severity:         "HIGH",
			Score:            7.5,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Heartbleed - Memory disclosure vulnerability",
		},
		{
			ID:               "CVE-2021-41773",
			Service:          "apache",
			AffectedVersions: []string{"2.4.49", "2.4.50"},
			Severity:         "CRITICAL",
			Score:            9.8,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Path traversal and RCE",
		},
		{
			ID:               "CVE-2019-0708",
			Service:          "rdp",
			AffectedVersions: []string{"*"},
			Severity:         "CRITICAL",
			Score:            9.8,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "BlueKeep - RDP RCE vulnerability",
		},

		// OpenSSH CVEs (7.4 is vulnerable to several)
		{
			ID:               "CVE-2016-10009",
			Service:          "openssh",
			AffectedVersions: []string{"6.8", "6.9", "7.0", "7.1", "7.2", "7.3", "7.4"},
			Severity:         "HIGH",
			Score:            7.5,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Privilege escalation via agent forwarding",
		},
		{
			ID:               "CVE-2016-10010",
			Service:          "openssh",
			AffectedVersions: []string{"7.4"},
			Severity:         "HIGH",
			Score:            6.8,
			Exploitable:      true,
			ExploitAvailable: false,
			ExploitDetails:   "Memory corruption in shared memory manager",
		},
		{
			ID:               "CVE-2016-10012",
			Service:          "openssh",
			AffectedVersions: []string{"7.4"},
			Severity:         "HIGH",
			Score:            7.2,
			Exploitable:      true,
			ExploitAvailable: false,
			ExploitDetails:   "Bounds checking in range of env variable",
		},
		{
			ID:               "CVE-2018-15473",
			Service:          "openssh",
			AffectedVersions: []string{"5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8", "5.9", "6.0", "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "7.7"},
			Severity:         "MEDIUM",
			Score:            5.3,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Username enumeration via timing attack",
		},

		// Pure-FTPd CVEs
		{
			ID:               "CVE-2020-9365",
			Service:          "pure-ftpd",
			AffectedVersions: []string{"1.0.42", "1.0.43", "1.0.44", "1.0.45", "1.0.46", "1.0.47", "1.0.48", "1.0.49"},
			Severity:         "HIGH",
			Score:            7.5,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Buffer overflow in log handling",
		},
		{
			ID:               "CVE-2019-20176",
			Service:          "pure-ftpd",
			AffectedVersions: []string{"1.0.49"},
			Severity:         "HIGH",
			Score:            7.5,
			Exploitable:      false,
			ExploitAvailable: false,
			ExploitDetails:   "Stack exhaustion in TLS negotiation",
		},

		// Apache HTTP Server CVEs (2.4.x versions)
		{
			ID:               "CVE-2021-41773",
			Service:          "apache",
			AffectedVersions: []string{"2.4.49", "2.4.50"},
			Severity:         "CRITICAL",
			Score:            9.8,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Path traversal and RCE",
		},
		{
			ID:               "CVE-2021-42013",
			Service:          "apache",
			AffectedVersions: []string{"2.4.49", "2.4.50"},
			Severity:         "CRITICAL",
			Score:            9.8,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Path traversal and RCE (bypass for CVE-2021-41773)",
		},
		{
			ID:               "CVE-2019-0211",
			Service:          "apache",
			AffectedVersions: []string{"2.4.17", "2.4.18", "2.4.19", "2.4.20", "2.4.21", "2.4.22", "2.4.23", "2.4.24", "2.4.25", "2.4.26", "2.4.27", "2.4.28", "2.4.29", "2.4.30", "2.4.31", "2.4.32", "2.4.33", "2.4.34", "2.4.35", "2.4.36", "2.4.37", "2.4.38"},
			Severity:         "CRITICAL",
			Score:            10.0,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Privilege escalation from www-data to root",
		},
		{
			ID:               "CVE-2017-15715",
			Service:          "apache",
			AffectedVersions: []string{"2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.6", "2.4.7", "2.4.9", "2.4.10", "2.4.12", "2.4.16", "2.4.17", "2.4.18", "2.4.20", "2.4.23", "2.4.24", "2.4.25", "2.4.27", "2.4.28", "2.4.29"},
			Severity:         "HIGH",
			Score:            8.1,
			Exploitable:      true,
			ExploitAvailable: true,
			ExploitDetails:   "Arbitrary file upload and RCE",
		},
	}

	for _, cve := range cves {
		v.cveDatabase[cve.ID] = cve
	}
}

// VerifyCVE verifies if a CVE is valid for the given service and version
func (v *CVEVerifier) VerifyCVE(cveID, service, version string) (*CVEInfo, bool) {
	// Normalize inputs
	cveID = strings.ToUpper(cveID)
	service = strings.ToLower(service)
	version = strings.TrimSpace(version)

	// Look up CVE in database
	cveDetails, exists := v.cveDatabase[cveID]
	if !exists {
		return nil, false
	}

	// Check if service matches
	if !strings.Contains(strings.ToLower(cveDetails.Service), service) &&
	   !strings.Contains(service, strings.ToLower(cveDetails.Service)) {
		return nil, false
	}

	// Check version match
	versionMatch := false
	if version != "" {
		versionMatch = v.isVersionAffected(version, cveDetails.AffectedVersions)
	} else {
		// If no version info, assume potential match but mark as unverified
		versionMatch = true
	}

	if !versionMatch {
		return nil, false
	}

	// Create verified CVE info
	cveInfo := &CVEInfo{
		ID:             cveDetails.ID,
		Severity:       cveDetails.Severity,
		Score:          cveDetails.Score,
		Service:        service,
		Version:        version,
		Verified:       versionMatch && version != "",
		Exploitable:    cveDetails.Exploitable,
		ExploitDetails: cveDetails.ExploitDetails,
	}

	return cveInfo, true
}

// isVersionAffected checks if a version is in the affected versions list
func (v *CVEVerifier) isVersionAffected(version string, affectedVersions []string) bool {
	// Wildcard match
	for _, av := range affectedVersions {
		if av == "*" {
			return true
		}

		// Exact match
		if strings.EqualFold(version, av) {
			return true
		}

		// Partial match for version strings
		if strings.Contains(strings.ToLower(version), strings.ToLower(av)) {
			return true
		}
	}

	// Try semantic version range matching
	return v.semanticVersionMatch(version, affectedVersions)
}

// semanticVersionMatch performs semantic version matching
func (v *CVEVerifier) semanticVersionMatch(version string, affectedVersions []string) bool {
	// Extract major.minor.patch from version string
	versionRegex := regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
	matches := versionRegex.FindStringSubmatch(version)

	if len(matches) < 3 {
		return false
	}

	for _, av := range affectedVersions {
		avMatches := versionRegex.FindStringSubmatch(av)
		if len(avMatches) < 3 {
			continue
		}

		// Compare major and minor versions
		if matches[1] == avMatches[1] && matches[2] == avMatches[2] {
			return true
		}
	}

	return false
}

// FindCVEsForService finds all CVEs matching a service and version
// This is the main function for automatic CVE discovery
func (v *CVEVerifier) FindCVEsForService(service, version string) []CVEInfo {
	service = strings.ToLower(service)
	version = strings.TrimSpace(version)

	// Normalize service names
	service = v.normalizeServiceName(service)

	var matchedCVEs []CVEInfo

	// Search through all CVEs in database
	for _, cveDetails := range v.cveDatabase {
		// Check if service matches
		serviceMatch := false
		cveService := strings.ToLower(cveDetails.Service)

		if strings.Contains(service, cveService) || strings.Contains(cveService, service) {
			serviceMatch = true
		}

		if !serviceMatch {
			continue
		}

		// Check version match
		versionMatch := false
		if version != "" {
			versionMatch = v.isVersionAffected(version, cveDetails.AffectedVersions)
		} else {
			// If no version, skip this CVE (no false positives)
			continue
		}

		if !versionMatch {
			continue
		}

		// Add matched CVE
		cveInfo := CVEInfo{
			ID:             cveDetails.ID,
			Severity:       cveDetails.Severity,
			Score:          cveDetails.Score,
			Service:        service,
			Version:        version,
			Verified:       true,
			Exploitable:    cveDetails.Exploitable,
			ExploitDetails: cveDetails.ExploitDetails,
		}

		matchedCVEs = append(matchedCVEs, cveInfo)
	}

	return matchedCVEs
}

// normalizeServiceName normalizes service names for matching
func (v *CVEVerifier) normalizeServiceName(service string) string {
	service = strings.ToLower(service)

	// Normalize common service name variations
	replacements := map[string]string{
		"ssh":          "openssh",
		"ftp":          "pure-ftpd",
		"httpd":        "apache",
		"apache httpd": "apache",
		"http":         "apache",
	}

	for old, new := range replacements {
		if strings.Contains(service, old) {
			return new
		}
	}

	return service
}

// VerifyMultipleCVEs verifies multiple CVEs at once
func (v *CVEVerifier) VerifyMultipleCVEs(cveIDs []string, service, version string) []*CVEInfo {
	var verified []*CVEInfo

	for _, cveID := range cveIDs {
		if cveInfo, ok := v.VerifyCVE(cveID, service, version); ok {
			verified = append(verified, cveInfo)
		}
	}

	return verified
}

// GetCVEDetails returns CVE details from database
func (v *CVEVerifier) GetCVEDetails(cveID string) (*CVEDetails, bool) {
	cveDetails, exists := v.cveDatabase[strings.ToUpper(cveID)]
	if !exists {
		return nil, false
	}
	return &cveDetails, true
}

// SearchCVEsByService finds all known CVEs for a service
func (v *CVEVerifier) SearchCVEsByService(service string) []CVEDetails {
	var results []CVEDetails
	service = strings.ToLower(service)

	for _, cve := range v.cveDatabase {
		if strings.Contains(strings.ToLower(cve.Service), service) {
			results = append(results, cve)
		}
	}

	return results
}

// FormatCVEList formats CVE list for display
func FormatCVEList(cves []CVEInfo, maxShow int) string {
	if len(cves) == 0 {
		return "None"
	}

	var parts []string
	limit := maxShow
	if len(cves) < limit {
		limit = len(cves)
	}

	for i := 0; i < limit; i++ {
		status := "VERIFIED"
		if cves[i].Exploitable {
			status = "EXPLOITABLE"
		}
		parts = append(parts, fmt.Sprintf("%s (%s/%.1f) [%s]",
			cves[i].ID,
			cves[i].Severity,
			cves[i].Score,
			status))
	}

	result := strings.Join(parts, ", ")
	if len(cves) > maxShow {
		result += fmt.Sprintf(" +%d more", len(cves)-maxShow)
	}

	return result
}
