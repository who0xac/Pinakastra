package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Finding represents an API discovery finding
type Finding struct {
	Type        string   `json:"type"`        // graphql, swagger, openapi, rest
	URL         string   `json:"url"`
	Endpoints   []string `json:"endpoints,omitempty"`
	Issue       string   `json:"issue"`       // introspection_enabled, exposed_docs, etc.
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
}

// Scanner performs API intelligence discovery
type Scanner struct {
	client  *http.Client
	timeout time.Duration
}

// NewScanner creates a new API scanner
func NewScanner(timeout int) *Scanner {
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

// ScanSubdomain scans a subdomain for API endpoints
func (s *Scanner) ScanSubdomain(ctx context.Context, subdomain string) []Finding {
	var findings []Finding

	// Check for GraphQL
	graphqlFindings := s.checkGraphQL(ctx, subdomain)
	findings = append(findings, graphqlFindings...)

	// Check for Swagger/OpenAPI
	swaggerFindings := s.checkSwagger(ctx, subdomain)
	findings = append(findings, swaggerFindings...)

	// Check for common API paths
	apiFindings := s.checkCommonAPIs(ctx, subdomain)
	findings = append(findings, apiFindings...)

	return findings
}

// checkGraphQL checks for GraphQL endpoints
func (s *Scanner) checkGraphQL(ctx context.Context, subdomain string) []Finding {
	var findings []Finding

	// Common GraphQL paths
	graphqlPaths := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/v2/graphql",
		"/query",
		"/api/query",
	}

	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, path := range graphqlPaths {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			url := baseURL + path

			// Test for GraphQL with introspection query
			introspectionQuery := `{"query":"{ __schema { types { name } } }"}`

			req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(introspectionQuery))
			if err != nil {
				continue
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			resp.Body.Close()

			bodyStr := string(body)

			// Check if it's GraphQL
			if strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "data") && resp.StatusCode == 200 {
				// It's GraphQL!
				finding := Finding{
					Type:        "graphql",
					URL:         url,
					Severity:    "high",
					Description: "GraphQL endpoint discovered",
				}

				// Check if introspection is enabled
				if strings.Contains(bodyStr, "types") && strings.Contains(bodyStr, "name") {
					finding.Issue = "introspection_enabled"
					finding.Severity = "critical"
					finding.Description = "GraphQL introspection is enabled - schema can be enumerated"

					// Try to extract some type names
					var result map[string]interface{}
					if json.Unmarshal(body, &result) == nil {
						if data, ok := result["data"].(map[string]interface{}); ok {
							if schema, ok := data["__schema"].(map[string]interface{}); ok {
								if types, ok := schema["types"].([]interface{}); ok {
									for i, t := range types {
										if i >= 10 {
											break
										}
										if typeMap, ok := t.(map[string]interface{}); ok {
											if name, ok := typeMap["name"].(string); ok {
												finding.Endpoints = append(finding.Endpoints, name)
											}
										}
									}
								}
							}
						}
					}
				}

				findings = append(findings, finding)
				break // Found GraphQL, no need to check other base URLs
			}

			time.Sleep(50 * time.Millisecond)
		}

		if len(findings) > 0 {
			break
		}
	}

	return findings
}

// checkSwagger checks for Swagger/OpenAPI documentation
func (s *Scanner) checkSwagger(ctx context.Context, subdomain string) []Finding {
	var findings []Finding

	// Common Swagger/OpenAPI paths
	swaggerPaths := []string{
		"/swagger.json",
		"/swagger.yaml",
		"/swagger/v1/swagger.json",
		"/api/swagger.json",
		"/api-docs",
		"/api/docs",
		"/docs",
		"/api/v1/docs",
		"/v1/api-docs",
		"/v2/api-docs",
		"/v3/api-docs",
		"/swagger-ui",
		"/swagger-ui.html",
		"/api/swagger-ui",
		"/openapi.json",
		"/openapi.yaml",
		"/api/openapi.json",
	}

	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, path := range swaggerPaths {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			url := baseURL + path

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept", "application/json, application/x-yaml, text/html")

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode != 200 {
				resp.Body.Close()
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB max
			resp.Body.Close()

			bodyStr := string(body)

			// Check if it's Swagger/OpenAPI
			isSwagger := strings.Contains(bodyStr, "swagger") || strings.Contains(bodyStr, "openapi")
			isSwagger = isSwagger || strings.Contains(bodyStr, "\"paths\"") || strings.Contains(bodyStr, "paths:")

			if isSwagger {
				finding := Finding{
					Type:        "swagger",
					URL:         url,
					Issue:       "api_documentation_exposed",
					Severity:    "medium",
					Description: "API documentation publicly accessible",
				}

				// Try to extract endpoints
				var endpoints []string

				// Try parsing as JSON
				var swagger map[string]interface{}
				if json.Unmarshal(body, &swagger) == nil {
					if paths, ok := swagger["paths"].(map[string]interface{}); ok {
						for path := range paths {
							endpoints = append(endpoints, path)
							if len(endpoints) >= 20 {
								break
							}
						}
					}
				} else {
					// Try regex for YAML or malformed JSON
					pathRegex := regexp.MustCompile(`(?m)^\s+(/[a-zA-Z0-9/_\-{}]+):`)
					matches := pathRegex.FindAllStringSubmatch(bodyStr, -1)
					for _, match := range matches {
						if len(match) > 1 {
							endpoints = append(endpoints, match[1])
							if len(endpoints) >= 20 {
								break
							}
						}
					}
				}

				finding.Endpoints = endpoints

				// Check for sensitive information
				if strings.Contains(bodyStr, "password") ||
				   strings.Contains(bodyStr, "secret") ||
				   strings.Contains(bodyStr, "token") ||
				   strings.Contains(bodyStr, "api_key") ||
				   strings.Contains(bodyStr, "apiKey") {
					finding.Severity = "high"
					finding.Description += " (may contain sensitive parameter information)"
				}

				findings = append(findings, finding)
				break
			}

			time.Sleep(50 * time.Millisecond)
		}

		if len(findings) > 0 {
			break
		}
	}

	return findings
}

// checkCommonAPIs checks for common API paths
func (s *Scanner) checkCommonAPIs(ctx context.Context, subdomain string) []Finding {
	var findings []Finding

	// Sensitive API paths
	sensitivePaths := []string{
		"/api/users",
		"/api/admin",
		"/api/config",
		"/api/settings",
		"/api/keys",
		"/api/secrets",
		"/admin/api",
		"/api/v1/users",
		"/api/v1/admin",
	}

	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, path := range sensitivePaths {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			url := baseURL + path

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept", "application/json")

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}

			resp.Body.Close()

			// Check for potentially sensitive endpoints (even if protected)
			if resp.StatusCode == 200 {
				findings = append(findings, Finding{
					Type:        "rest",
					URL:         url,
					Issue:       "sensitive_endpoint_accessible",
					Severity:    "high",
					Description: "Sensitive API endpoint is accessible",
				})
			} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
				findings = append(findings, Finding{
					Type:        "rest",
					URL:         url,
					Issue:       "sensitive_endpoint_exists",
					Severity:    "medium",
					Description: "Sensitive API endpoint exists (protected)",
				})
			}

			time.Sleep(50 * time.Millisecond)
		}

		if len(findings) > 0 {
			break
		}
	}

	return findings
}

// ScanBatch scans multiple subdomains (sequential)
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

		time.Sleep(200 * time.Millisecond)
	}

	return results
}

// GetCriticalFindings returns critical/high severity findings
func GetCriticalFindings(findings []Finding) []Finding {
	var critical []Finding
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			critical = append(critical, f)
		}
	}
	return critical
}

// GroupByType groups findings by type
func GroupByType(findings []Finding) map[string][]Finding {
	grouped := make(map[string][]Finding)
	for _, f := range findings {
		grouped[f.Type] = append(grouped[f.Type], f)
	}
	return grouped
}
