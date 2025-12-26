package cors

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Issue represents a CORS misconfiguration
type Issue struct {
	Subdomain   string   `json:"subdomain"`
	Type        string   `json:"type"`        // wildcard, credentials, null_origin, etc.
	Severity    string   `json:"severity"`    // critical, high, medium, low
	Description string   `json:"description"`
	Headers     []string `json:"headers"`     // Problematic headers
	Evidence    string   `json:"evidence"`
}

// Checker performs CORS misconfiguration detection
type Checker struct {
	client  *http.Client
	timeout time.Duration
}

// NewChecker creates a new CORS checker
func NewChecker(timeout int) *Checker {
	return &Checker{
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

// CheckSubdomain checks for CORS misconfigurations on a subdomain with concurrent execution
func (c *Checker) CheckSubdomain(ctx context.Context, subdomain string) []Issue {
	var issues []Issue

	// Test with different origins
	testOrigins := []string{
		"https://evil.com",
		"https://attacker.com",
		"null",
		"https://"+subdomain+".evil.com",
	}

	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	issuesChan := make(chan *Issue, len(urls)*len(testOrigins))
	semaphore := make(chan struct{}, 4) // Limit to 4 concurrent CORS tests

	totalTests := 0
	for _, baseURL := range urls {
		for _, origin := range testOrigins {
			select {
			case <-ctx.Done():
				return issues
			default:
			}

			totalTests++
			semaphore <- struct{}{} // Acquire
			go func(url, orig string) {
				defer func() { <-semaphore }() // Release

				issue := c.testOrigin(ctx, url, orig, subdomain)
				issuesChan <- issue
			}(baseURL, origin)
		}
	}

	// Collect all results
	for i := 0; i < totalTests; i++ {
		issue := <-issuesChan
		if issue != nil {
			issues = append(issues, *issue)
		}
	}
	close(issuesChan)

	// Deduplicate issues
	issues = deduplicateIssues(issues)

	return issues
}

// testOrigin tests a specific origin
func (c *Checker) testOrigin(ctx context.Context, url, origin, subdomain string) *Issue {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	// Set Origin header
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check CORS headers in response
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "" {
		return nil // No CORS headers
	}

	// Check for wildcard with credentials (CRITICAL)
	if acao == "*" && acac == "true" {
		return &Issue{
			Subdomain:   subdomain,
			Type:        "wildcard_with_credentials",
			Severity:    "critical",
			Description: "CORS allows all origins (*) with credentials - allows any website to read sensitive data",
			Headers: []string{
				fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
				fmt.Sprintf("Access-Control-Allow-Credentials: %s", acac),
			},
			Evidence: "Attacker can steal user data from any origin",
		}
	}

	// Check for wildcard (HIGH)
	if acao == "*" {
		return &Issue{
			Subdomain:   subdomain,
			Type:        "wildcard_origin",
			Severity:    "high",
			Description: "CORS allows all origins (*) - any website can make requests",
			Headers: []string{
				fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
			},
			Evidence: "Any website can read responses",
		}
	}

	// Check if origin is reflected (CRITICAL if with credentials)
	if acao == origin {
		if acac == "true" {
			return &Issue{
				Subdomain:   subdomain,
				Type:        "reflected_origin_with_credentials",
				Severity:    "critical",
				Description: fmt.Sprintf("CORS reflects arbitrary origin '%s' with credentials", origin),
				Headers: []string{
					fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
					fmt.Sprintf("Access-Control-Allow-Credentials: %s", acac),
				},
				Evidence: "Attacker can read authenticated user data",
			}
		}

		// Even without credentials, reflected origin is a medium issue
		return &Issue{
			Subdomain:   subdomain,
			Type:        "reflected_origin",
			Severity:    "medium",
			Description: fmt.Sprintf("CORS reflects arbitrary origin '%s'", origin),
			Headers: []string{
				fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
			},
			Evidence: "Potential for exploitation depending on application",
		}
	}

	// Check for null origin (MEDIUM-HIGH)
	if acao == "null" && origin == "null" {
		severity := "medium"
		if acac == "true" {
			severity = "high"
		}

		return &Issue{
			Subdomain:   subdomain,
			Type:        "null_origin",
			Severity:    severity,
			Description: "CORS allows 'null' origin (exploitable via sandbox iframe)",
			Headers: []string{
				fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
			},
			Evidence: "Attacker can use sandboxed iframe to exploit",
		}
	}

	// Check for pre-domain wildcard (MEDIUM)
	if strings.HasPrefix(acao, "https://") || strings.HasPrefix(acao, "http://") {
		// Extract domain from ACAO
		acaoDomain := strings.TrimPrefix(acao, "https://")
		acaoDomain = strings.TrimPrefix(acaoDomain, "http://")

		// Check if it's a subdomain-based reflection
		if strings.Contains(acaoDomain, "."+subdomain) {
			return &Issue{
				Subdomain:   subdomain,
				Type:        "subdomain_reflection",
				Severity:    "medium",
				Description: "CORS trusts subdomains (attacker may register subdomain)",
				Headers: []string{
					fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
				},
				Evidence: "Subdomain takeover may lead to CORS bypass",
			}
		}
	}

	return nil
}

// deduplicateIssues removes duplicate issues
func deduplicateIssues(issues []Issue) []Issue {
	seen := make(map[string]bool)
	var unique []Issue

	for _, issue := range issues {
		key := fmt.Sprintf("%s-%s", issue.Subdomain, issue.Type)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, issue)
		}
	}

	return unique
}

// CheckBatch checks multiple subdomains (sequential)
func (c *Checker) CheckBatch(ctx context.Context, subdomains []string) map[string][]Issue {
	results := make(map[string][]Issue)

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		issues := c.CheckSubdomain(ctx, subdomain)
		if len(issues) > 0 {
			results[subdomain] = issues
		}

		time.Sleep(100 * time.Millisecond)
	}

	return results
}

// GetCriticalIssues returns only critical severity issues
func GetCriticalIssues(issues []Issue) []Issue {
	var critical []Issue
	for _, issue := range issues {
		if issue.Severity == "critical" {
			critical = append(critical, issue)
		}
	}
	return critical
}

// GroupBySeverity groups issues by severity
func GroupBySeverity(issues []Issue) map[string][]Issue {
	grouped := make(map[string][]Issue)
	for _, issue := range issues {
		grouped[issue.Severity] = append(grouped[issue.Severity], issue)
	}
	return grouped
}
