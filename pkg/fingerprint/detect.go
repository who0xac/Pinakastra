package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Technology represents a detected technology
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence"`
	CVEs       []string `json:"cves,omitempty"`
}

// Scanner performs technology fingerprinting
type Scanner struct {
	client           *http.Client
	compiledPatterns map[string]*regexp.Regexp
	timeout          time.Duration
}

// NewScanner creates a new fingerprint scanner
func NewScanner(timeout int) *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:        100,
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
		compiledPatterns: CompilePatterns(),
		timeout:          time.Duration(timeout) * time.Second,
	}
}

// DetectTechnologies scans a subdomain and detects technologies
func (s *Scanner) DetectTechnologies(ctx context.Context, subdomain string) []Technology {
	var detected []Technology
	seen := make(map[string]bool) // Prevent duplicates

	// Try HTTPS first, then HTTP
	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	var resp *http.Response
	var body []byte
	var err error
	var req *http.Request

	for _, url := range urls {
		select {
		case <-ctx.Done():
			return detected
		default:
		}

		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		// Set realistic headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")

		resp, err = s.client.Do(req)
		if err != nil {
			continue
		}

		// Read body (limit to 5MB)
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()

		if len(body) > 0 {
			break // Successfully got response
		}
	}

	if resp == nil || len(body) == 0 {
		return detected
	}

	bodyStr := string(body)

	// Detect technologies using patterns
	for _, pattern := range TechnologyPatterns {
		if seen[pattern.Name] {
			continue
		}

		match := false
		version := ""

		// Check headers
		if len(pattern.Headers) > 0 {
			for headerName, headerPattern := range pattern.Headers {
				headerValue := resp.Header.Get(headerName)
				if headerValue != "" {
					if re, exists := s.compiledPatterns[headerPattern]; exists {
						if re.MatchString(headerValue) {
							match = true
							// Try to extract version
							if pattern.ImpliesVersionFromHeader == headerName {
								if matches := re.FindStringSubmatch(headerValue); len(matches) > 1 {
									version = matches[1]
								}
							}
							break
						}
					}
				}
			}
		}

		// Check cookies
		if !match && len(pattern.Cookies) > 0 {
			cookies := resp.Cookies()
			for _, cookie := range cookies {
				if cookiePattern, exists := pattern.Cookies[cookie.Name]; exists {
					if re, err := regexp.Compile(cookiePattern); err == nil {
						if re.MatchString(cookie.Value) || cookiePattern == ".+" {
							match = true
							break
						}
					}
				}
			}
		}

		// Check body patterns
		if !match && len(pattern.Patterns) > 0 {
			for _, bodyPattern := range pattern.Patterns {
				if re, exists := s.compiledPatterns[bodyPattern]; exists {
					if re.MatchString(bodyStr) {
						match = true
						// Try to extract version
						if pattern.ImpliesVersionFromBody != "" {
							if versionRe, vExists := s.compiledPatterns[pattern.ImpliesVersionFromBody]; vExists {
								if matches := versionRe.FindStringSubmatch(bodyStr); len(matches) > 1 {
									version = matches[1]
								}
							}
						}
						break
					}
				}
			}
		}

		// Check script sources
		if !match && len(pattern.Script) > 0 {
			for _, scriptPattern := range pattern.Script {
				if strings.Contains(bodyStr, scriptPattern) {
					match = true
					break
				}
			}
		}

		// Check meta tags
		if !match && len(pattern.Meta) > 0 {
			for metaName, metaPattern := range pattern.Meta {
				// Simple meta tag extraction
				metaRegex := regexp.MustCompile(fmt.Sprintf(`<meta[^>]*name=["\']%s["\'][^>]*content=["\']([^"\']+)["\']`, metaName))
				if matches := metaRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
					if re, err := regexp.Compile(metaPattern); err == nil {
						if re.MatchString(matches[1]) {
							match = true
							// Try to extract version
							if versionMatches := re.FindStringSubmatch(matches[1]); len(versionMatches) > 1 {
								version = versionMatches[1]
							}
							break
						}
					}
				}
			}
		}

		if match {
			seen[pattern.Name] = true
			detected = append(detected, Technology{
				Name:       pattern.Name,
				Category:   pattern.Category,
				Version:    version,
				Confidence: pattern.Confidence,
			})
		}
	}

	return detected
}

// DetectBatch detects technologies for multiple subdomains (sequential to avoid crashes)
func (s *Scanner) DetectBatch(ctx context.Context, subdomains []string) map[string][]Technology {
	results := make(map[string][]Technology)

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		techs := s.DetectTechnologies(ctx, subdomain)
		if len(techs) > 0 {
			results[subdomain] = techs
		}

		// Small delay to be polite
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

// GetCategoryCount returns count of technologies by category
func GetCategoryCount(technologies []Technology) map[string]int {
	counts := make(map[string]int)
	for _, tech := range technologies {
		counts[tech.Category]++
	}
	return counts
}

// FilterByCategory filters technologies by category
func FilterByCategory(technologies []Technology, category string) []Technology {
	var filtered []Technology
	for _, tech := range technologies {
		if tech.Category == category {
			filtered = append(filtered, tech)
		}
	}
	return filtered
}

// HasTechnology checks if a specific technology is in the list
func HasTechnology(technologies []Technology, name string) bool {
	for _, tech := range technologies {
		if strings.EqualFold(tech.Name, name) {
			return true
		}
	}
	return false
}

// GetTechnology returns a specific technology from the list
func GetTechnology(technologies []Technology, name string) *Technology {
	for i := range technologies {
		if strings.EqualFold(technologies[i].Name, name) {
			return &technologies[i]
		}
	}
	return nil
}
