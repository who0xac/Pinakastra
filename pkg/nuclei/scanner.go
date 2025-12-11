package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Vulnerability represents a nuclei finding
type Vulnerability struct {
	TemplateID   string   `json:"template_id"`
	Name         string   `json:"name"`
	Severity     string   `json:"severity"`
	Type         string   `json:"type"`
	Host         string   `json:"host"`
	MatchedAt    string   `json:"matched_at"`
	Description  string   `json:"description"`
	Reference    []string `json:"reference,omitempty"`
	CVE          string   `json:"cve,omitempty"`
	CWE          []string `json:"cwe,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	ExtractedResults []string `json:"extracted_results,omitempty"`
	CURLCommand  string   `json:"curl_command,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// Scanner manages nuclei vulnerability scanning
type Scanner struct {
	nucleiPath    string
	templatesPath string
	concurrency   int
	timeout       int
	verbose       bool
	mu            sync.Mutex
}

// NewScanner creates a new nuclei scanner
func NewScanner(concurrency, timeout int) (*Scanner, error) {
	// Find nuclei binary
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		return nil, fmt.Errorf("nuclei not found in PATH: %w", err)
	}

	// Get nuclei templates directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	templatesPath := filepath.Join(homeDir, "nuclei-templates")
	if _, err := os.Stat(templatesPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("nuclei templates not found at %s (run 'nuclei -update-templates')", templatesPath)
	}

	return &Scanner{
		nucleiPath:    nucleiPath,
		templatesPath: templatesPath,
		concurrency:   concurrency,
		timeout:       timeout,
		verbose:       false,
	}, nil
}

// ScanTargets runs nuclei against multiple targets
func (s *Scanner) ScanTargets(ctx context.Context, targets []string, technologies []string) ([]Vulnerability, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Create temporary target file
	targetFile, err := os.CreateTemp("", "pinakastra-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create target file: %w", err)
	}
	defer os.Remove(targetFile.Name())

	// Write targets to file
	for _, target := range targets {
		if _, err := targetFile.WriteString(target + "\n"); err != nil {
			targetFile.Close()
			return nil, fmt.Errorf("failed to write target: %w", err)
		}
	}
	targetFile.Close()

	// Create output file for JSON results
	outputFile, err := os.CreateTemp("", "pinakastra-nuclei-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	// Select templates based on detected technologies
	templates := s.selectTemplates(technologies)

	// Build nuclei command
	args := []string{
		"-l", targetFile.Name(),
		"-json",
		"-o", outputFile.Name(),
		"-severity", "critical,high,medium",
		"-c", fmt.Sprintf("%d", s.concurrency),
		"-timeout", fmt.Sprintf("%d", s.timeout),
		"-retries", "1",
		"-no-update-templates",
		"-silent",
	}

	// Add template selection
	if len(templates) > 0 {
		args = append(args, "-tags", strings.Join(templates, ","))
	}

	// Run nuclei
	cmd := exec.CommandContext(ctx, s.nucleiPath, args...)
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		// Nuclei returns non-zero exit code when vulnerabilities are found
		// Only return error if it's not exit code 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("nuclei scan failed: %w", err)
			}
		}
	}

	// Parse results
	vulns, err := s.parseResults(outputFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	return vulns, nil
}

// ScanWithTemplates runs specific nuclei templates
func (s *Scanner) ScanWithTemplates(ctx context.Context, targets []string, templatePaths []string) ([]Vulnerability, error) {
	if len(targets) == 0 || len(templatePaths) == 0 {
		return nil, nil
	}

	// Create temporary target file
	targetFile, err := os.CreateTemp("", "pinakastra-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create target file: %w", err)
	}
	defer os.Remove(targetFile.Name())

	for _, target := range targets {
		if _, err := targetFile.WriteString(target + "\n"); err != nil {
			targetFile.Close()
			return nil, fmt.Errorf("failed to write target: %w", err)
		}
	}
	targetFile.Close()

	// Create output file
	outputFile, err := os.CreateTemp("", "pinakastra-nuclei-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	// Build command with specific templates
	args := []string{
		"-l", targetFile.Name(),
		"-json",
		"-o", outputFile.Name(),
		"-c", fmt.Sprintf("%d", s.concurrency),
		"-timeout", fmt.Sprintf("%d", s.timeout),
		"-retries", "1",
		"-no-update-templates",
		"-silent",
	}

	// Add templates
	for _, tmpl := range templatePaths {
		args = append(args, "-t", tmpl)
	}

	cmd := exec.CommandContext(ctx, s.nucleiPath, args...)
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("nuclei scan failed: %w", err)
			}
		}
	}

	return s.parseResults(outputFile.Name())
}

// parseResults parses nuclei JSON output
func (s *Scanner) parseResults(outputPath string) ([]Vulnerability, error) {
	file, err := os.Open(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open results file: %w", err)
	}
	defer file.Close()

	var vulns []Vulnerability
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue // Skip malformed lines
		}

		vuln := s.parseVulnerability(result)
		if vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading results: %w", err)
	}

	return vulns, nil
}

// parseVulnerability converts nuclei JSON to Vulnerability struct
func (s *Scanner) parseVulnerability(data map[string]interface{}) *Vulnerability {
	info, ok := data["info"].(map[string]interface{})
	if !ok {
		return nil
	}

	vuln := &Vulnerability{
		Timestamp: time.Now(),
	}

	// Template ID
	if templateID, ok := data["template-id"].(string); ok {
		vuln.TemplateID = templateID
	}

	// Name
	if name, ok := info["name"].(string); ok {
		vuln.Name = name
	}

	// Severity
	if severity, ok := info["severity"].(string); ok {
		vuln.Severity = strings.ToLower(severity)
	}

	// Type
	if typ, ok := data["type"].(string); ok {
		vuln.Type = typ
	}

	// Host
	if host, ok := data["host"].(string); ok {
		vuln.Host = host
	}

	// Matched At
	if matchedAt, ok := data["matched-at"].(string); ok {
		vuln.MatchedAt = matchedAt
	} else {
		vuln.MatchedAt = vuln.Host
	}

	// Description
	if desc, ok := info["description"].(string); ok {
		vuln.Description = desc
	}

	// Reference
	if ref, ok := info["reference"].([]interface{}); ok {
		for _, r := range ref {
			if refStr, ok := r.(string); ok {
				vuln.Reference = append(vuln.Reference, refStr)
			}
		}
	}

	// CVE
	if classification, ok := info["classification"].(map[string]interface{}); ok {
		if cveID, ok := classification["cve-id"].(string); ok {
			vuln.CVE = cveID
		}
		if cweID, ok := classification["cwe-id"].([]interface{}); ok {
			for _, cwe := range cweID {
				if cweStr, ok := cwe.(string); ok {
					vuln.CWE = append(vuln.CWE, cweStr)
				}
			}
		}
	}

	// Tags
	if tags, ok := info["tags"].([]interface{}); ok {
		for _, tag := range tags {
			if tagStr, ok := tag.(string); ok {
				vuln.Tags = append(vuln.Tags, tagStr)
			}
		}
	} else if tagsStr, ok := info["tags"].(string); ok {
		vuln.Tags = strings.Split(tagsStr, ",")
	}

	// Extracted results
	if extracted, ok := data["extracted-results"].([]interface{}); ok {
		for _, ex := range extracted {
			if exStr, ok := ex.(string); ok {
				vuln.ExtractedResults = append(vuln.ExtractedResults, exStr)
			}
		}
	}

	// CURL command
	if curl, ok := data["curl-command"].(string); ok {
		vuln.CURLCommand = curl
	}

	return vuln
}

// selectTemplates selects nuclei templates based on detected technologies
func (s *Scanner) selectTemplates(technologies []string) []string {
	templateTags := make(map[string]bool)

	for _, tech := range technologies {
		techLower := strings.ToLower(tech)

		// Map technologies to nuclei tags
		switch {
		// Web servers
		case strings.Contains(techLower, "apache"):
			templateTags["apache"] = true
		case strings.Contains(techLower, "nginx"):
			templateTags["nginx"] = true
		case strings.Contains(techLower, "iis"):
			templateTags["iis"] = true
		case strings.Contains(techLower, "tomcat"):
			templateTags["tomcat"] = true

		// CMS
		case strings.Contains(techLower, "wordpress"):
			templateTags["wordpress"] = true
		case strings.Contains(techLower, "drupal"):
			templateTags["drupal"] = true
		case strings.Contains(techLower, "joomla"):
			templateTags["joomla"] = true
		case strings.Contains(techLower, "magento"):
			templateTags["magento"] = true
		case strings.Contains(techLower, "shopify"):
			templateTags["shopify"] = true

		// Frameworks
		case strings.Contains(techLower, "laravel"):
			templateTags["laravel"] = true
		case strings.Contains(techLower, "django"):
			templateTags["django"] = true
		case strings.Contains(techLower, "flask"):
			templateTags["flask"] = true
		case strings.Contains(techLower, "rails"):
			templateTags["rails"] = true
		case strings.Contains(techLower, "spring"):
			templateTags["spring"] = true
		case strings.Contains(techLower, "struts"):
			templateTags["struts"] = true

		// Databases
		case strings.Contains(techLower, "mysql"):
			templateTags["mysql"] = true
		case strings.Contains(techLower, "postgresql"):
			templateTags["postgresql"] = true
		case strings.Contains(techLower, "mongodb"):
			templateTags["mongodb"] = true
		case strings.Contains(techLower, "redis"):
			templateTags["redis"] = true
		case strings.Contains(techLower, "elasticsearch"):
			templateTags["elasticsearch"] = true

		// APIs
		case strings.Contains(techLower, "graphql"):
			templateTags["graphql"] = true
		case strings.Contains(techLower, "swagger"):
			templateTags["swagger"] = true
		case strings.Contains(techLower, "api"):
			templateTags["api"] = true

		// Cloud
		case strings.Contains(techLower, "aws"):
			templateTags["aws"] = true
		case strings.Contains(techLower, "azure"):
			templateTags["azure"] = true
		case strings.Contains(techLower, "gcp"):
			templateTags["gcp"] = true

		// Other
		case strings.Contains(techLower, "jenkins"):
			templateTags["jenkins"] = true
		case strings.Contains(techLower, "gitlab"):
			templateTags["gitlab"] = true
		case strings.Contains(techLower, "docker"):
			templateTags["docker"] = true
		case strings.Contains(techLower, "kubernetes"):
			templateTags["kubernetes"] = true
		}
	}

	// Always scan for common vulnerabilities
	templateTags["cve"] = true
	templateTags["exposure"] = true
	templateTags["misconfig"] = true
	templateTags["default-logins"] = true

	// Convert to slice
	tags := make([]string, 0, len(templateTags))
	for tag := range templateTags {
		tags = append(tags, tag)
	}

	return tags
}

// GetCriticalVulnerabilities filters critical/high vulnerabilities
func GetCriticalVulnerabilities(vulns []Vulnerability) []Vulnerability {
	var critical []Vulnerability
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			critical = append(critical, v)
		}
	}
	return critical
}

// GroupBySeverity groups vulnerabilities by severity
func GroupBySeverity(vulns []Vulnerability) map[string][]Vulnerability {
	grouped := make(map[string][]Vulnerability)
	for _, v := range vulns {
		grouped[v.Severity] = append(grouped[v.Severity], v)
	}
	return grouped
}

// GetUniqueCVEs extracts unique CVE IDs
func GetUniqueCVEs(vulns []Vulnerability) []string {
	seen := make(map[string]bool)
	var cves []string

	for _, v := range vulns {
		if v.CVE != "" && !seen[v.CVE] {
			seen[v.CVE] = true
			cves = append(cves, v.CVE)
		}
	}

	return cves
}
