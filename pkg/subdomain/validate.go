package subdomain

import (
	"regexp"
	"strings"
)

func validateSubdomains(subdomains []string, baseDomain string) []string {
	valid := []string{}
	subdomainRegex := regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

	for _, subdomain := range subdomains {
		subdomain = strings.TrimSpace(strings.ToLower(subdomain))

		if subdomain == "" {
			continue
		}

		if !subdomainRegex.MatchString(subdomain) {
			continue
		}

		if !strings.HasPrefix(subdomain, "*.") && !strings.HasSuffix(subdomain, "."+baseDomain) && subdomain != baseDomain {
			continue
		}

		if isIPAddress(subdomain) {
			continue
		}

		valid = append(valid, subdomain)
	}

	return valid
}

func isIPAddress(s string) bool {
	ipv4Regex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if ipv4Regex.MatchString(s) {
		return true
	}

	if strings.Contains(s, ":") && strings.Count(s, ":") >= 2 {
		return true
	}

	return false
}

func isValidDomain(domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))

	if !strings.Contains(domain, ".") {
		return false
	}

	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}
