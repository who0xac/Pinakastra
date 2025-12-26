package intelligence

import (
	"context"
	"fmt"
	"strings"

	"github.com/who0xac/pinakastra/pkg/ollama"
)

// ServiceAnalysis contains AI analysis results for a service
type ServiceAnalysis struct {
	IP             string
	Port           int
	Service        string
	Version        string
	IsOutdated     bool
	LatestVersion  string
	Vulnerabilities []string
	Exploitability string // NONE, LOW, MODERATE, HIGH, CRITICAL
}

// ServiceAnalyzer analyzes network services using AI
type ServiceAnalyzer struct {
	ollamaClient   *ollama.Client
	nvdClient      *NVDClient
	versionChecker *VersionChecker
}

// NewServiceAnalyzer creates a new service analyzer
func NewServiceAnalyzer(model string) *ServiceAnalyzer {
	return &ServiceAnalyzer{
		ollamaClient:   ollama.NewClient(model),
		nvdClient:      NewNVDClient(""), // No API key for now
		versionChecker: NewVersionChecker(),
	}
}

// AnalyzeService analyzes a single service using AI
func (a *ServiceAnalyzer) AnalyzeService(ctx context.Context, ip string, port int, service, version, product string) (*ServiceAnalysis, error) {
	// Build service description
	serviceDesc := service
	if product != "" {
		serviceDesc = product
	}
	if version != "" {
		serviceDesc = fmt.Sprintf("%s %s", serviceDesc, version)
	}

	// Check latest version using web scraping (more reliable than AI)
	latestVersion := ""
	isOutdated := false
	if version != "" {
		latest, outdated, err := a.versionChecker.GetLatestVersion(ctx, service, version)
		if err == nil && latest != "" {
			latestVersion = latest
			isOutdated = outdated
		}
	}

	// Create prompt for AI
	prompt := a.buildPrompt(serviceDesc, service, version)

	// Call Ollama
	response, err := a.ollamaClient.Chat(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %v", err)
	}

	// Parse AI response
	analysis := a.parseResponse(response, ip, port, service, version)

	// Use web-scraped version info if we have it (more reliable)
	if latestVersion != "" {
		analysis.LatestVersion = latestVersion
		analysis.IsOutdated = isOutdated
	}

	// Verify CVEs against NIST NVD database to filter out fake/hallucinated CVEs
	if len(analysis.Vulnerabilities) > 0 {
		originalCount := len(analysis.Vulnerabilities)
		verifiedCVEs := a.nvdClient.VerifyMultipleCVEs(ctx, analysis.Vulnerabilities)

		// Replace with only verified CVEs that match the product
		analysis.Vulnerabilities = []string{}
		maxExploitLevel := "NONE"

		// Extract product name from service (e.g., "Apache httpd" -> "apache")
		productKeywords := a.extractProductKeywords(service, product)

		for _, cve := range verifiedCVEs {
			// Check if CVE is actually for this product
			if !a.isCVEForProduct(cve, productKeywords) {
				// CVE exists but is for a different product - skip it
				continue
			}

			analysis.Vulnerabilities = append(analysis.Vulnerabilities, cve.ID)

			// Calculate exploitability based on CVE severity and description
			exploitLevel := a.calculateExploitability(cve)
			if a.isHigherExploitLevel(exploitLevel, maxExploitLevel) {
				maxExploitLevel = exploitLevel
			}
		}

		// Update exploitability if we found verified CVEs
		if len(analysis.Vulnerabilities) > 0 {
			analysis.Exploitability = maxExploitLevel
		} else if originalCount > 0 {
			// AI suggested CVEs but none were verified or matched product
			analysis.Exploitability = "NONE"
		}
	}

	return analysis, nil
}

// buildPrompt creates the prompt for AI analysis
func (a *ServiceAnalyzer) buildPrompt(serviceDesc, service, version string) string {
	if version == "" {
		return fmt.Sprintf(`Analyze this network service: %s

CRITICAL: Only provide REAL, VERIFIED CVE IDs. Do NOT make up or guess CVE numbers.
If you don't know exact CVEs, say "Unknown" instead of inventing them.

First identify:
- Service type: Network service / Web service / Database / Other
- Service category: FTP / SSH / HTTP / MySQL / etc.

Then provide:
1. Is this service version outdated? (Yes/No and latest stable version if known)
2. ONLY list CVE IDs you are CERTAIN exist for this exact service (verify the CVE is for the right service, not a different product)
3. Initial exploitability assessment (will be verified later)

Keep response concise and factual. Format:
SERVICE_TYPE: [type]
OUTDATED: [Yes/No]
LATEST: [version]
VULNERABILITIES: [CVE-XXXX-XXXXX, CVE-YYYY-YYYYY] or Unknown
EXPLOITABILITY: [NONE/LOW/MODERATE/HIGH/CRITICAL]`, serviceDesc)
	}

	return fmt.Sprintf(`Analyze this network service: %s (version: %s)

CRITICAL INSTRUCTIONS:
1. Product Matching: Only provide CVEs for "%s", not similar products (e.g., Apache CVEs only for Apache, not Nginx or Cisco)
2. Version Research: Look up the ACTUAL latest stable version number for %s
3. CVE Verification: Only list CVE IDs you are CERTAIN exist for this exact product
4. No Guessing: If unsure about latest version or CVEs, say "Unknown"

Service Information:
- Product: %s
- Current Version: %s
- Determine if %s is the latest stable release

Required Output Format:
SERVICE_TYPE: [Network service/Web service/Database/Other]
OUTDATED: [Yes/No]
LATEST: [exact version number, e.g., "9.8p1" or "2.4.62"]
VULNERABILITIES: [CVE-YYYY-NNNNN, CVE-YYYY-NNNNN] or Unknown
EXPLOITABILITY: [NONE/LOW/MODERATE/HIGH/CRITICAL]

IMPORTANT:
- LATEST must be an actual version number (e.g., "8.2", "2.4.62", "9.8p1")
- Do NOT use "latest", "current", "newest" - use the SPECIFIC version number
- All CVEs will be verified against NIST NVD - fake CVEs will be filtered out
- CVEs must match the product "%s" specifically`,
		serviceDesc, version, service, service, service, version, version, service)
}

// parseResponse parses AI response into structured analysis
func (a *ServiceAnalyzer) parseResponse(response, ip string, port int, service, version string) *ServiceAnalysis {
	analysis := &ServiceAnalysis{
		IP:             ip,
		Port:           port,
		Service:        service,
		Version:        version,
		IsOutdated:     false,
		LatestVersion:  "",
		Vulnerabilities: []string{},
		Exploitability: "UNKNOWN",
	}

	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse OUTDATED status
		if strings.HasPrefix(line, "OUTDATED:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "OUTDATED:"))
			analysis.IsOutdated = strings.ToLower(value) == "yes"
		}

		// Parse LATEST version
		if strings.HasPrefix(line, "LATEST:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "LATEST:"))
			if value != "" && value != "N/A" && value != "Unknown" {
				analysis.LatestVersion = value
			}
		}

		// Parse VULNERABILITIES
		if strings.HasPrefix(line, "VULNERABILITIES:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "VULNERABILITIES:"))
			if value != "" && value != "None" && value != "N/A" && value != "Unknown" {
				// Extract CVE IDs
				cves := a.extractCVEs(value)
				analysis.Vulnerabilities = cves
			}
		}

		// Parse EXPLOITABILITY
		if strings.HasPrefix(line, "EXPLOITABILITY:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "EXPLOITABILITY:"))
			value = strings.ToUpper(value)
			if value == "NONE" || value == "LOW" || value == "MODERATE" || value == "HIGH" || value == "CRITICAL" {
				analysis.Exploitability = value
			}
		}
	}

	// Fallback: Try to extract CVEs from entire response if not found
	if len(analysis.Vulnerabilities) == 0 {
		analysis.Vulnerabilities = a.extractCVEs(response)
	}

	return analysis
}

// extractCVEs extracts CVE IDs from text
func (a *ServiceAnalyzer) extractCVEs(text string) []string {
	var cves []string
	words := strings.Fields(text)

	for _, word := range words {
		// Remove common separators
		word = strings.Trim(word, ".,;:[](){}")

		// Check if it's a CVE
		if len(word) >= 13 && strings.HasPrefix(word, "CVE-") {
			// Validate format: CVE-YYYY-NNNNN
			parts := strings.Split(word, "-")
			if len(parts) == 3 && len(parts[1]) == 4 {
				cves = append(cves, word)
			}
		}
	}

	return cves
}

// IsAvailable checks if Ollama service is available
func (a *ServiceAnalyzer) IsAvailable(ctx context.Context) bool {
	return a.ollamaClient.IsAvailable(ctx)
}

// CheckModel verifies if the model is available
func (a *ServiceAnalyzer) CheckModel(ctx context.Context) (bool, error) {
	return a.ollamaClient.CheckModel(ctx)
}

// extractProductKeywords extracts keywords from service and product name for matching
func (a *ServiceAnalyzer) extractProductKeywords(service, product string) []string {
	keywords := []string{}

	// Split service name and add parts
	serviceParts := strings.Fields(strings.ToLower(service))
	keywords = append(keywords, serviceParts...)

	// Split product name and add parts
	if product != "" {
		productParts := strings.Fields(strings.ToLower(product))
		keywords = append(keywords, productParts...)
	}

	// Add common variations
	for _, part := range keywords {
		// Remove common suffixes
		part = strings.TrimSuffix(part, "d") // httpd -> http
		if !contains(keywords, part) && len(part) > 2 {
			keywords = append(keywords, part)
		}
	}

	return keywords
}

// isCVEForProduct checks if a CVE description mentions the product
func (a *ServiceAnalyzer) isCVEForProduct(cve *CVEInfo, productKeywords []string) bool {
	description := strings.ToLower(cve.Description)

	// Check if any product keyword appears in the description
	matchCount := 0
	for _, keyword := range productKeywords {
		if len(keyword) < 3 {
			continue // Skip very short keywords
		}
		if strings.Contains(description, keyword) {
			matchCount++
		}
	}

	// Require at least one keyword match
	// This filters out CVEs for completely different products
	return matchCount > 0
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// calculateExploitability determines exploitability level from CVE data
func (a *ServiceAnalyzer) calculateExploitability(cve *CVEInfo) string {
	// Base level on CVSS score and severity
	score := cve.Score
	severity := strings.ToUpper(cve.Severity)
	description := strings.ToLower(cve.Description)

	// CRITICAL exploitability (CVSS 9.0-10.0 + RCE keywords)
	if score >= 9.0 && severity == "CRITICAL" {
		rceKeywords := []string{
			"remote code execution",
			"rce",
			"arbitrary code execution",
			"command injection",
			"code injection",
		}
		for _, keyword := range rceKeywords {
			if strings.Contains(description, keyword) {
				return "CRITICAL"
			}
		}
	}

	// HIGH exploitability (CVSS 7.0-8.9 or HIGH severity with exploit keywords)
	if (score >= 7.0 && score < 9.0) || severity == "HIGH" {
		highKeywords := []string{
			"remote code execution",
			"rce",
			"code execution",
			"authentication bypass",
			"privilege escalation",
			"buffer overflow",
			"sql injection",
			"command injection",
		}
		for _, keyword := range highKeywords {
			if strings.Contains(description, keyword) {
				return "HIGH"
			}
		}
		// Default for HIGH severity without specific keywords
		if severity == "HIGH" {
			return "MODERATE"
		}
	}

	// MODERATE exploitability (CVSS 4.0-6.9 or MEDIUM severity)
	if (score >= 4.0 && score < 7.0) || severity == "MEDIUM" {
		return "MODERATE"
	}

	// LOW exploitability (CVSS < 4.0 or LOW severity)
	if score < 4.0 || severity == "LOW" {
		return "LOW"
	}

	// Default to MODERATE if we can't determine
	return "MODERATE"
}

// isHigherExploitLevel compares two exploit levels
func (a *ServiceAnalyzer) isHigherExploitLevel(level1, level2 string) bool {
	levels := map[string]int{
		"NONE":     0,
		"UNKNOWN":  1,
		"LOW":      2,
		"MODERATE": 3,
		"HIGH":     4,
		"CRITICAL": 5,
	}

	return levels[level1] > levels[level2]
}
