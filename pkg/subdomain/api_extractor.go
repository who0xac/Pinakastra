package subdomain

import (
	"strings"
)

// ExtractAPIs extracts potential API endpoints from subdomains
func ExtractAPIs(subdomains []string) []string {
	apis := make([]string, 0)

	// API-related keywords to search for
	apiKeywords := []string{
		"api",
		"api1", "api2", "api3",
		"apiv1", "apiv2", "apiv3",
		"api-v1", "api-v2", "api-v3",
		"rest",
		"restapi",
		"graphql",
		"gql",
		"gateway",
		"api-gateway",
		"webhook",
		"backend",
		"service",
		"microservice",
		"grpc",
		"rpc",
		"ws",
		"wss",
		"soap",
	}

	seen := make(map[string]bool)

	for _, subdomain := range subdomains {
		lowerSubdomain := strings.ToLower(subdomain)

		// Check if subdomain contains any API-related keywords
		for _, keyword := range apiKeywords {
			if strings.Contains(lowerSubdomain, keyword) {
				if !seen[subdomain] {
					apis = append(apis, subdomain)
					seen[subdomain] = true
					break
				}
			}
		}
	}

	return apis
}
