package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Details contains enriched CVE information from NIST NVD
type Details struct {
	ID               string    `json:"id"`
	Description      string    `json:"description"`
	CVSSScore        float64   `json:"cvss_score"`
	CVSSVector       string    `json:"cvss_vector"`
	Severity         string    `json:"severity"`
	CWE              []string  `json:"cwe"`
	References       []string  `json:"references"`
	PublishedDate    time.Time `json:"published_date"`
	ModifiedDate     time.Time `json:"modified_date"`
	ExploitAvailable bool      `json:"exploit_available"`
}

// Fetcher fetches CVE details from NIST NVD API
type Fetcher struct {
	client  *http.Client
	cache   map[string]*Details
	apiKey  string // Optional NVD API key for higher rate limits
}

// NewFetcher creates a new CVE fetcher
func NewFetcher(apiKey string) *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:  make(map[string]*Details),
		apiKey: apiKey,
	}
}

// Fetch retrieves CVE details from NIST NVD API
func (f *Fetcher) Fetch(ctx context.Context, cveID string) (*Details, error) {
	// Check cache first
	if cached, ok := f.cache[cveID]; ok {
		return cached, nil
	}

	// Build NVD API URL
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add API key if available (for higher rate limits)
	if f.apiKey != "" {
		req.Header.Set("apiKey", f.apiKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse NVD API response
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Published string `json:"published"`
				Modified  string `json:"lastModified"`
				Metrics   struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore      float64 `json:"baseScore"`
							VectorString   string  `json:"vectorString"`
							BaseSeverity   string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV2 []struct {
						CVSSData struct {
							BaseScore      float64 `json:"baseScore"`
							VectorString   string  `json:"vectorString"`
						} `json:"cvssData"`
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found in NVD: %s", cveID)
	}

	vuln := nvdResp.Vulnerabilities[0].CVE
	details := &Details{
		ID: vuln.ID,
	}

	// Extract description (English)
	for _, desc := range vuln.Descriptions {
		if desc.Lang == "en" {
			details.Description = desc.Value
			break
		}
	}

	// Extract CVSS score (prefer v3.1, fallback to v2)
	if len(vuln.Metrics.CVSSMetricV31) > 0 {
		metric := vuln.Metrics.CVSSMetricV31[0]
		details.CVSSScore = metric.CVSSData.BaseScore
		details.CVSSVector = metric.CVSSData.VectorString
		details.Severity = strings.ToLower(metric.CVSSData.BaseSeverity)
	} else if len(vuln.Metrics.CVSSMetricV2) > 0 {
		metric := vuln.Metrics.CVSSMetricV2[0]
		details.CVSSScore = metric.CVSSData.BaseScore
		details.CVSSVector = metric.CVSSData.VectorString
		details.Severity = strings.ToLower(metric.BaseSeverity)
	}

	// Extract CWE
	for _, weakness := range vuln.Weaknesses {
		for _, desc := range weakness.Description {
			if desc.Lang == "en" {
				details.CWE = append(details.CWE, desc.Value)
			}
		}
	}

	// Extract references
	for _, ref := range vuln.References {
		details.References = append(details.References, ref.URL)

		// Check if exploit is available
		refLower := strings.ToLower(ref.URL)
		if strings.Contains(refLower, "exploit-db") ||
		   strings.Contains(refLower, "exploit") ||
		   strings.Contains(refLower, "poc") {
			details.ExploitAvailable = true
		}
	}

	// Parse dates
	details.PublishedDate, _ = time.Parse(time.RFC3339, vuln.Published)
	details.ModifiedDate, _ = time.Parse(time.RFC3339, vuln.Modified)

	// Cache the result
	f.cache[cveID] = details

	return details, nil
}

// FetchBatch fetches multiple CVEs (with rate limiting)
func (f *Fetcher) FetchBatch(ctx context.Context, cveIDs []string) map[string]*Details {
	results := make(map[string]*Details)

	for _, cveID := range cveIDs {
		details, err := f.Fetch(ctx, cveID)
		if err != nil {
			// Skip CVEs that fail to fetch
			continue
		}
		results[cveID] = details

		// Rate limiting: NIST allows 5 requests per 30 seconds without API key
		time.Sleep(6 * time.Second)
	}

	return results
}

// Merge merges local CVE data (from Nuclei) with online data (from NIST)
func Merge(local *Details, online *Details) *Details {
	if online == nil {
		return local
	}

	if local == nil {
		return online
	}

	// Start with online data (more complete)
	merged := *online

	// Add local references if not in online
	for _, ref := range local.References {
		if !contains(merged.References, ref) {
			merged.References = append(merged.References, ref)
		}
	}

	// Prefer local severity if more specific
	if local.Severity != "" && online.Severity == "" {
		merged.Severity = local.Severity
	}

	return &merged
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
