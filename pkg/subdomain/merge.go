package subdomain

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func deduplicateSubdomains(subdomains []string) []string {
	seen := make(map[string]bool)
	unique := []string{}

	for _, subdomain := range subdomains {
		subdomain = strings.TrimSpace(strings.ToLower(subdomain))
		if subdomain == "" {
			continue
		}
		if !seen[subdomain] {
			seen[subdomain] = true
			unique = append(unique, subdomain)
		}
	}

	return unique
}

func readLinesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lines := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func parseLinesFromString(input string) []string {
	lines := strings.Split(input, "\n")
	result := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}

	return result
}

func saveSubdomains(path string, subdomains []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, subdomain := range subdomains {
		if _, err := writer.WriteString(subdomain + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

// cleanAndMergeSubdomains merges all subdomain files, cleans them, and deduplicates
func cleanAndMergeSubdomains(outputDir, domain string) ([]string, error) {

	// Tool output files
	toolFiles := []string{
		"subfinder.txt",
		"findomain.txt",
		"assetfinder.txt",
		"sublist3r.txt",
		"chaos.txt",
		"crtsh.txt",
		"shodan.txt",
		"puredns.txt",
	}

	allSubdomains := []string{}

	// Read and clean each tool's output
	for _, toolFile := range toolFiles {
		filePath := filepath.Join(outputDir, toolFile)

		// Skip if file doesn't exist
		if !fileExists(filePath) {
			continue
		}

		// Read raw lines
		lines, err := readLinesFromFile(filePath)
		if err != nil {
			// Silently skip files that can't be read
			continue
		}

		// Clean each line
		for _, line := range lines {
			cleaned := cleanSubdomain(line, domain)
			if cleaned != "" {
				allSubdomains = append(allSubdomains, cleaned)
			}
		}
	}

	// Deduplicate and sort
	unique := deduplicateSubdomains(allSubdomains)

	// Save to all_subdomains.txt
	allSubdomainsFile := filepath.Join(outputDir, "all_subdomains.txt")
	if err := saveSubdomains(allSubdomainsFile, unique); err != nil {
		return nil, fmt.Errorf("failed to save merged subdomains: %v", err)
	}

	return unique, nil
}

// cleanSubdomain cleans a single subdomain string
func cleanSubdomain(subdomain, baseDomain string) string {
	// Convert to lowercase
	subdomain = strings.ToLower(subdomain)

	// Trim whitespace
	subdomain = strings.TrimSpace(subdomain)

	// Remove trailing dot
	subdomain = strings.TrimSuffix(subdomain, ".")

	// Remove protocol if present
	subdomain = strings.TrimPrefix(subdomain, "http://")
	subdomain = strings.TrimPrefix(subdomain, "https://")

	// Remove path if present
	if idx := strings.Index(subdomain, "/"); idx != -1 {
		subdomain = subdomain[:idx]
	}

	// Remove port if present
	if idx := strings.Index(subdomain, ":"); idx != -1 {
		subdomain = subdomain[:idx]
	}

	// Must belong to base domain
	if !strings.HasSuffix(subdomain, baseDomain) && subdomain != baseDomain {
		return ""
	}

	// Basic validation - must be valid domain format
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9_-]+\.)+` + regexp.QuoteMeta(baseDomain) + `$`)
	if !domainRegex.MatchString(subdomain) && subdomain != baseDomain {
		return ""
	}

	return subdomain
}
