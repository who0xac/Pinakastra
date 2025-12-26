package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NVDClient handles NIST NVD API requests
type NVDClient struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
	rateLimit  time.Duration
	lastCall   time.Time
}

// NVDResponse represents the NVD API response
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Format          string `json:"format"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Published   string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CvssMetricV2 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// NewNVDClient creates a new NVD API client
func NewNVDClient(apiKey string) *NVDClient {
	return &NVDClient{
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		apiKey:    apiKey,
		rateLimit: 6 * time.Second, // NIST requires 6 seconds between requests without API key
		lastCall:  time.Time{},
	}
}

// VerifyCVE verifies if a CVE exists in the NIST NVD database
func (c *NVDClient) VerifyCVE(ctx context.Context, cveID string) (*CVEInfo, error) {
	// Rate limiting
	c.rateLimit = 6 * time.Second
	if c.apiKey != "" {
		c.rateLimit = 600 * time.Millisecond // With API key: 50 requests per 30 seconds
	}

	if !c.lastCall.IsZero() {
		elapsed := time.Since(c.lastCall)
		if elapsed < c.rateLimit {
			time.Sleep(c.rateLimit - elapsed)
		}
	}
	c.lastCall = time.Now()

	// Normalize CVE ID
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		return nil, fmt.Errorf("invalid CVE ID format: %s", cveID)
	}

	// Build request URL
	params := url.Values{}
	params.Set("cveId", cveID)

	reqURL := fmt.Sprintf("%s?%s", c.baseURL, params.Encode())

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add API key if available
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query NVD: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Check if CVE was found
	if nvdResp.TotalResults == 0 {
		return nil, fmt.Errorf("CVE not found in NIST NVD database")
	}

	// Extract CVE information
	vuln := nvdResp.Vulnerabilities[0].CVE

	cveInfo := &CVEInfo{
		ID:           vuln.ID,
		Verified:     true,
		PublishedDate: vuln.Published,
		LastModified: vuln.LastModified,
	}

	// Get description
	for _, desc := range vuln.Descriptions {
		if desc.Lang == "en" {
			cveInfo.Description = desc.Value
			break
		}
	}

	// Get CVSS score and severity (prefer v3.1, then v3.0, then v2)
	if len(vuln.Metrics.CvssMetricV31) > 0 {
		cveInfo.Score = vuln.Metrics.CvssMetricV31[0].CvssData.BaseScore
		cveInfo.Severity = vuln.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
	} else if len(vuln.Metrics.CvssMetricV30) > 0 {
		cveInfo.Score = vuln.Metrics.CvssMetricV30[0].CvssData.BaseScore
		cveInfo.Severity = vuln.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
	} else if len(vuln.Metrics.CvssMetricV2) > 0 {
		cveInfo.Score = vuln.Metrics.CvssMetricV2[0].CvssData.BaseScore
		cveInfo.Severity = vuln.Metrics.CvssMetricV2[0].BaseSeverity
	}

	// Determine exploitability based on severity and keywords
	cveInfo.Exploitable = c.isExploitable(cveInfo.Description, cveInfo.Severity)

	return cveInfo, nil
}

// VerifyMultipleCVEs verifies multiple CVEs with rate limiting
func (c *NVDClient) VerifyMultipleCVEs(ctx context.Context, cveIDs []string) []*CVEInfo {
	var verified []*CVEInfo

	for _, cveID := range cveIDs {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return verified
		default:
		}

		cveInfo, err := c.VerifyCVE(ctx, cveID)
		if err != nil {
			// Skip invalid CVEs silently
			continue
		}

		verified = append(verified, cveInfo)
	}

	return verified
}

// isExploitable determines if a CVE is likely exploitable based on description
func (c *NVDClient) isExploitable(description, severity string) bool {
	// High/Critical severity is more likely exploitable
	if severity == "HIGH" || severity == "CRITICAL" {
		// Check for RCE/exploit keywords
		exploitKeywords := []string{
			"remote code execution",
			"rce",
			"code execution",
			"arbitrary code",
			"exploit",
			"overflow",
			"injection",
			"authentication bypass",
			"privilege escalation",
		}

		descLower := strings.ToLower(description)
		for _, keyword := range exploitKeywords {
			if strings.Contains(descLower, keyword) {
				return true
			}
		}
	}

	return false
}
