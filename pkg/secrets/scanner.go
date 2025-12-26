package secrets

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Finding represents a discovered secret
type Finding struct {
	Type        string `json:"type"`
	Match       string `json:"match"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Source      string `json:"source"`       // URL where found
	LineNumber  int    `json:"line_number"`  // Line number in file
	Context     string `json:"context"`      // Surrounding context
}

// Scanner performs secret scanning
type Scanner struct {
	client  *http.Client
	timeout time.Duration
}

// NewScanner creates a new secrets scanner
func NewScanner(timeout int) *Scanner {
	CompilePatterns() // Compile patterns on initialization

	return &Scanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		timeout: time.Duration(timeout) * time.Second,
	}
}

// ScanSubdomain scans a subdomain for secrets in JS files with concurrent execution
// This is BETTER than GodEye - we scan ACTUAL target JS files, not GitHub
func (s *Scanner) ScanSubdomain(ctx context.Context, subdomain string) []Finding {
	var allFindings []Finding

	// Step 1: Get the main page HTML
	jsFiles := s.findJSFiles(ctx, subdomain)

	if len(jsFiles) == 0 {
		return allFindings
	}

	// Step 2: Scan each JS file for secrets concurrently
	findingsChan := make(chan []Finding, len(jsFiles))
	semaphore := make(chan struct{}, 10) // Limit to 10 concurrent JS file scans

	for _, jsURL := range jsFiles {
		select {
		case <-ctx.Done():
			return allFindings
		default:
		}

		semaphore <- struct{}{} // Acquire
		go func(url string) {
			defer func() { <-semaphore }() // Release

			findings := s.scanJSFile(ctx, url)
			if len(findings) > 0 {
				findingsChan <- findings
			} else {
				findingsChan <- []Finding{}
			}
		}(jsURL)
	}

	// Collect all results
	for i := 0; i < len(jsFiles); i++ {
		findings := <-findingsChan
		allFindings = append(allFindings, findings...)
	}
	close(findingsChan)

	return allFindings
}

// findJSFiles extracts JS file URLs from a subdomain
func (s *Scanner) findJSFiles(ctx context.Context, subdomain string) []string {
	var jsFiles []string
	seen := make(map[string]bool)

	// Try HTTPS first, then HTTP
	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	var body []byte
	var baseURL string

	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}

		body, _ = io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
		resp.Body.Close()

		if len(body) > 0 {
			baseURL = url
			break
		}
	}

	if len(body) == 0 {
		return jsFiles
	}

	bodyStr := string(body)

	// Extract JS files from <script src="...">
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)[^"']*["']`)
	matches := scriptRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, match := range matches {
		if len(match) > 1 {
			jsURL := match[1]

			// Convert relative URLs to absolute
			if strings.HasPrefix(jsURL, "//") {
				jsURL = "https:" + jsURL
			} else if strings.HasPrefix(jsURL, "/") {
				// Relative to domain root
				if strings.HasPrefix(baseURL, "https://") {
					jsURL = "https://" + subdomain + jsURL
				} else {
					jsURL = "http://" + subdomain + jsURL
				}
			} else if !strings.HasPrefix(jsURL, "http") {
				// Relative to current page
				jsURL = baseURL + "/" + jsURL
			}

			// Filter out external JS (CDNs, etc.)
			if strings.Contains(jsURL, subdomain) && !seen[jsURL] {
				seen[jsURL] = true
				jsFiles = append(jsFiles, jsURL)
			}
		}
	}

	// Also look for inline webpack/bundle references
	webpackRegex := regexp.MustCompile(`(/_next/static/chunks/|/static/js/|/assets/js/|/js/|/build/|/dist/)([a-zA-Z0-9._-]+\.js)`)
	webpackMatches := webpackRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, match := range webpackMatches {
		if len(match) > 0 {
			jsPath := match[0]
			jsURL := ""

			if strings.HasPrefix(baseURL, "https://") {
				jsURL = "https://" + subdomain + jsPath
			} else {
				jsURL = "http://" + subdomain + jsPath
			}

			if !seen[jsURL] {
				seen[jsURL] = true
				jsFiles = append(jsFiles, jsURL)
			}
		}
	}

	return jsFiles
}

// scanJSFile scans a single JS file for secrets
func (s *Scanner) scanJSFile(ctx context.Context, jsURL string) []Finding {
	var findings []Finding

	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return findings
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return findings
	}

	// Read JS file content (limit to 5MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return findings
	}

	content := string(body)
	lines := strings.Split(content, "\n")

	// Scan with each pattern
	for _, pattern := range SecretPatterns {
		matches := pattern.Regex.FindAllStringSubmatchIndex(content, -1)

		for _, matchIdx := range matches {
			if len(matchIdx) < 2 {
				continue
			}

			// Get the full match
			matchStart := matchIdx[0]
			matchEnd := matchIdx[1]
			match := content[matchStart:matchEnd]

			// Check for false positives
			if pattern.IsFalsePositive(match) {
				continue
			}

			// If pattern requires entropy check, validate it
			if pattern.Entropy > 0 {
				// Extract the value part (usually second capture group)
				var value string
				if len(matchIdx) >= 4 {
					value = content[matchIdx[2]:matchIdx[3]]
				} else {
					value = match
				}

				entropy := calculateEntropy(value)
				if entropy < pattern.Entropy {
					continue // Skip low entropy matches
				}
			}

			// Find line number
			lineNum := findLineNumber(content, matchStart)

			// Get context (surrounding lines)
			context := getContext(lines, lineNum, 1)

			findings = append(findings, Finding{
				Type:        pattern.Name,
				Match:       sanitizeMatch(match),
				Severity:    pattern.Severity,
				Description: pattern.Description,
				Source:      jsURL,
				LineNumber:  lineNum,
				Context:     context,
			})
		}
	}

	return findings
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// findLineNumber finds the line number of a position in content
func findLineNumber(content string, pos int) int {
	if pos >= len(content) {
		pos = len(content) - 1
	}

	lineNum := 1
	for i := 0; i < pos; i++ {
		if content[i] == '\n' {
			lineNum++
		}
	}

	return lineNum
}

// getContext returns surrounding lines for context
func getContext(lines []string, lineNum, contextLines int) string {
	if lineNum < 1 || lineNum > len(lines) {
		return ""
	}

	start := lineNum - 1 - contextLines
	if start < 0 {
		start = 0
	}

	end := lineNum + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	contextSlice := lines[start:end]
	return strings.Join(contextSlice, "\n")
}

// sanitizeMatch sanitizes sensitive data in match (show full value for verification)
func sanitizeMatch(match string) string {
	// Show full value so user can verify if it's real or false positive
	// Users need to see the full key to determine if it's actually sensitive
	// (e.g., Flash CLSID D27CDB6E-AE6D-11CF-96B8-444553540000 is not a secret)
	return match
}

// ScanBatch scans multiple subdomains (sequential to avoid crashes)
func (s *Scanner) ScanBatch(ctx context.Context, subdomains []string) map[string][]Finding {
	results := make(map[string][]Finding)

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		findings := s.ScanSubdomain(ctx, subdomain)
		if len(findings) > 0 {
			results[subdomain] = findings
		}

		// Delay between subdomains
		time.Sleep(200 * time.Millisecond)
	}

	return results
}

// GroupBySeverity groups findings by severity
func GroupBySeverity(findings []Finding) map[string][]Finding {
	grouped := make(map[string][]Finding)
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}
	return grouped
}

// GetCriticalFindings returns only critical severity findings
func GetCriticalFindings(findings []Finding) []Finding {
	var critical []Finding
	for _, f := range findings {
		if f.Severity == "critical" {
			critical = append(critical, f)
		}
	}
	return critical
}

// FormatForSave formats findings for saving to file (with URLs and line numbers)
func FormatForSave(findings []Finding) string {
	var output strings.Builder

	output.WriteString("=== SECRETS FOUND ===\n\n")

	bySeverity := GroupBySeverity(findings)

	// Critical first
	if critical, exists := bySeverity["critical"]; exists && len(critical) > 0 {
		output.WriteString("[CRITICAL]\n")
		for _, f := range critical {
			output.WriteString(fmt.Sprintf("  %s: %s:%d\n", f.Type, f.Source, f.LineNumber))
			output.WriteString(fmt.Sprintf("    Match: %s\n", f.Match))
			output.WriteString(fmt.Sprintf("    Description: %s\n\n", f.Description))
		}
	}

	// High
	if high, exists := bySeverity["high"]; exists && len(high) > 0 {
		output.WriteString("[HIGH]\n")
		for _, f := range high {
			output.WriteString(fmt.Sprintf("  %s: %s:%d\n", f.Type, f.Source, f.LineNumber))
			output.WriteString(fmt.Sprintf("    Match: %s\n\n", f.Match))
		}
	}

	// Medium
	if medium, exists := bySeverity["medium"]; exists && len(medium) > 0 {
		output.WriteString("[MEDIUM]\n")
		for _, f := range medium {
			output.WriteString(fmt.Sprintf("  %s: %s:%d\n", f.Type, f.Source, f.LineNumber))
		}
		output.WriteString("\n")
	}

	return output.String()
}
