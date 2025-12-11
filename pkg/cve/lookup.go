package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// CVEInfo represents CVE information
type CVEInfo struct {
	ID          string
	Description string
	Severity    string
	CVSS        float64
	Published   string
	Exploitable bool
	ExploitDB   []string
}

// Lookup searches for CVEs related to a service
type Lookup struct {
	client *http.Client
}

// NewLookup creates a new CVE lookup instance
func NewLookup() *Lookup {
	return &Lookup{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SearchByService searches CVEs by service name and version
func (l *Lookup) SearchByService(ctx context.Context, service, version string) ([]CVEInfo, error) {
	if service == "" {
		return nil, nil
	}

	var allCVEs []CVEInfo

	// Try searchsploit first (local, faster)
	if exploits := l.searchExploitDB(service, version); len(exploits) > 0 {
		allCVEs = append(allCVEs, exploits...)
	}

	// Then try NVD API
	if nvdCVEs, err := l.searchNVD(ctx, service, version); err == nil {
		allCVEs = append(allCVEs, nvdCVEs...)
	}

	return deduplicateCVEs(allCVEs), nil
}

// SearchByCVE gets detailed info for a specific CVE ID
func (l *Lookup) SearchByCVE(ctx context.Context, cveID string) (*CVEInfo, error) {
	if !isValidCVE(cveID) {
		return nil, fmt.Errorf("invalid CVE ID: %s", cveID)
	}

	// Try NVD API first
	if cve, err := l.getCVEFromNVD(ctx, cveID); err == nil {
		return cve, nil
	}

	// Fallback to basic info
	return &CVEInfo{
		ID:          cveID,
		Description: "CVE details unavailable",
	}, nil
}

// searchExploitDB uses searchsploit to find local exploits
func (l *Lookup) searchExploitDB(service, version string) []CVEInfo {
	// Check if searchsploit is available
	if _, err := exec.LookPath("searchsploit"); err != nil {
		return nil
	}

	query := service
	if version != "" {
		query = fmt.Sprintf("%s %s", service, version)
	}

	cmd := exec.Command("searchsploit", "--json", query)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var result struct {
		Results []struct {
			Title string `json:"Title"`
			Path  string `json:"Path"`
			EDBId string `json:"EDB-ID"`
		} `json:"RESULTS_EXPLOIT"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil
	}

	var cves []CVEInfo
	for _, exploit := range result.Results {
		// Extract CVE from title if present
		cveID := extractCVEFromTitle(exploit.Title)

		cve := CVEInfo{
			ID:          cveID,
			Description: exploit.Title,
			Exploitable: true,
			ExploitDB:   []string{exploit.EDBId},
		}

		cves = append(cves, cve)
	}

	return cves
}

// searchNVD searches the National Vulnerability Database
func (l *Lookup) searchNVD(ctx context.Context, service, version string) ([]CVEInfo, error) {
	// NVD API v2 endpoint
	keyword := service
	if version != "" {
		keyword = fmt.Sprintf("%s %s", service, version)
	}

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=10",
		strings.ReplaceAll(keyword, " ", "+"))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description []struct {
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSv3 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
							Severity  string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				Published string `json:"published"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var cves []CVEInfo
	for _, vuln := range result.Vulnerabilities {
		cve := CVEInfo{
			ID:        vuln.CVE.ID,
			Published: vuln.CVE.Published,
		}

		// Get description
		if len(vuln.CVE.Description) > 0 {
			cve.Description = vuln.CVE.Description[0].Value
		}

		// Get CVSS score
		if len(vuln.CVE.Metrics.CVSSv3) > 0 {
			cve.CVSS = vuln.CVE.Metrics.CVSSv3[0].CVSSData.BaseScore
			cve.Severity = vuln.CVE.Metrics.CVSSv3[0].CVSSData.Severity
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

// getCVEFromNVD gets detailed info for a specific CVE
func (l *Lookup) getCVEFromNVD(ctx context.Context, cveID string) (*CVEInfo, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description []struct {
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSv3 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
							Severity  string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				Published string `json:"published"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found")
	}

	vuln := result.Vulnerabilities[0]
	cve := &CVEInfo{
		ID:        vuln.CVE.ID,
		Published: vuln.CVE.Published,
	}

	// Get description
	if len(vuln.CVE.Description) > 0 {
		cve.Description = vuln.CVE.Description[0].Value
	}

	// Get CVSS score
	if len(vuln.CVE.Metrics.CVSSv3) > 0 {
		cve.CVSS = vuln.CVE.Metrics.CVSSv3[0].CVSSData.BaseScore
		cve.Severity = vuln.CVE.Metrics.CVSSv3[0].CVSSData.Severity
	}

	return cve, nil
}

// extractCVEFromTitle extracts CVE ID from exploit title
func extractCVEFromTitle(title string) string {
	words := strings.Fields(title)
	for _, word := range words {
		if isValidCVE(word) {
			return word
		}
	}
	return "CVE-UNKNOWN"
}

// isValidCVE checks if string is a valid CVE ID
func isValidCVE(s string) bool {
	if len(s) < 13 {
		return false
	}
	return strings.HasPrefix(s, "CVE-") && s[4] >= '1' && s[4] <= '9'
}

// deduplicateCVEs removes duplicate CVEs by ID
func deduplicateCVEs(cves []CVEInfo) []CVEInfo {
	seen := make(map[string]bool)
	var result []CVEInfo

	for _, cve := range cves {
		if !seen[cve.ID] {
			seen[cve.ID] = true
			result = append(result, cve)
		}
	}

	return result
}
