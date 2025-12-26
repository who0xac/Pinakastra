package urldiscovery

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// SmartFilter provides intelligent URL filtering and deduplication
type SmartFilter struct {
	MaxURLsPerSubdomain int
	MaxURLsPerPattern   int
}

// NewSmartFilter creates a new smart filter with default limits
func NewSmartFilter() *SmartFilter {
	return &SmartFilter{
		MaxURLsPerSubdomain: 150,  // Limit total URLs per subdomain
		MaxURLsPerPattern:   5,    // Limit similar URLs (same path pattern)
	}
}

// FilterURLs applies smart filtering to reduce URL set while maintaining coverage
func (sf *SmartFilter) FilterURLs(urls []string) []string {
	if len(urls) == 0 {
		return urls
	}

	// Step 1: Remove static files
	filtered := sf.removeStaticFiles(urls)

	// Step 2: Deduplicate exact duplicates (already done by merger, but safety check)
	filtered = removeDuplicates(filtered)

	// Step 3: Group by endpoint pattern and limit per pattern
	filtered = sf.limitByPattern(filtered)

	// Step 4: Prioritize URLs with parameters (more likely to be vulnerable)
	filtered = sf.prioritizeParameterized(filtered)

	// Step 5: Apply final limit per subdomain if still too many
	if len(filtered) > sf.MaxURLsPerSubdomain {
		filtered = filtered[:sf.MaxURLsPerSubdomain]
	}

	return filtered
}

// removeStaticFiles filters out static assets that are unlikely to have vulnerabilities
func (sf *SmartFilter) removeStaticFiles(urls []string) []string {
	// IMPORTANT: Keep sensitive files and JS for analysis
	// Sensitive file patterns (ALWAYS KEEP THESE)
	sensitiveFiles := regexp.MustCompile(`\.(` +
		`env|sql|db|sqlite|bak|backup|old|config|conf|` +
		`key|pem|crt|cer|p12|pfx|` + // Certificates/keys
		`log|logs|dump|` + // Logs
		`git|svn|htaccess|htpasswd` + // Version control/config
		`)(\?|#|$)`)

	// KEEP regular .js files (for JS analysis in active exploitation)
	// Only remove JS bundles/minified that are unlikely to have issues
	jsExtensions := regexp.MustCompile(`\.(` +
		`min\.js|bundle\.js|chunk\.js|vendor\.js|webpack\.js|` +
		`jquery.*\.js|bootstrap.*\.js|angular.*\.js|react.*\.js|vue.*\.js` + // Common libraries
		`)(\?|#|$)`)

	// Only remove truly static assets (images, fonts, CSS, media)
	staticExtensions := regexp.MustCompile(`\.(` +
		// Images
		`png|jpg|jpeg|gif|svg|ico|webp|bmp|tiff|` +
		// Stylesheets
		`css|scss|sass|less|` +
		// Fonts
		`woff|woff2|ttf|eot|otf|` +
		// Documents (PDFs, Office files)
		`pdf|doc|docx|xls|xlsx|ppt|pptx|` +
		// Media
		`mp4|mp3|avi|mov|wmv|flv|wav|ogg|` +
		// Other truly static
		`map` +
		`)(\?|#|$)`)

	// Static asset paths (but be selective - keep uploads, config, admin paths)
	staticPaths := []string{
		"/cdn-cgi/",      // Cloudflare CDN
		"/node_modules/", // NPM packages
	}

	var filtered []string
	for _, u := range urls {
		urlLower := strings.ToLower(u)

		// ALWAYS KEEP sensitive files (highest priority)
		if sensitiveFiles.MatchString(urlLower) {
			filtered = append(filtered, u)
			continue
		}

		// KEEP important paths even if in "static" folders
		importantPaths := []string{
			"admin", "api", "auth", "login", "upload", "config",
			"backup", "debug", "console", "panel", ".env", ".git",
		}
		isImportant := false
		for _, keyword := range importantPaths {
			if strings.Contains(urlLower, keyword) {
				isImportant = true
				break
			}
		}
		if isImportant {
			filtered = append(filtered, u)
			continue
		}

		// Skip JS bundles/libraries but KEEP regular .js files
		if jsExtensions.MatchString(urlLower) {
			continue
		}

		// Skip truly static files (images, CSS, fonts, media)
		if staticExtensions.MatchString(urlLower) {
			continue
		}

		// Skip static CDN paths
		isStatic := false
		for _, path := range staticPaths {
			if strings.Contains(urlLower, path) {
				isStatic = true
				break
			}
		}
		if isStatic {
			continue
		}

		filtered = append(filtered, u)
	}

	return filtered
}

// limitByPattern groups URLs by path pattern and limits similar URLs
func (sf *SmartFilter) limitByPattern(urls []string) []string {
	// Group URLs by normalized path pattern
	patternGroups := make(map[string][]string)

	for _, u := range urls {
		pattern := sf.extractPattern(u)
		patternGroups[pattern] = append(patternGroups[pattern], u)
	}

	// Limit each pattern group and collect results
	var filtered []string
	for _, group := range patternGroups {
		// Sort group to prioritize URLs with parameters
		sort.Slice(group, func(i, j int) bool {
			return sf.urlScore(group[i]) > sf.urlScore(group[j])
		})

		// Take top N from each pattern group
		limit := sf.MaxURLsPerPattern
		if len(group) < limit {
			limit = len(group)
		}
		filtered = append(filtered, group[:limit]...)
	}

	return filtered
}

// extractPattern extracts a normalized pattern from URL
// Example: /api/users/123 -> /api/users/{id}
//          /products?id=5&sort=name -> /products?params
func (sf *SmartFilter) extractPattern(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	path := parsed.Path

	// Replace numeric IDs with {id}
	numericPattern := regexp.MustCompile(`/\d+`)
	path = numericPattern.ReplaceAllString(path, "/{id}")

	// Replace UUIDs with {uuid}
	uuidPattern := regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	path = uuidPattern.ReplaceAllString(path, "/{uuid}")

	// Replace hash-like strings with {hash}
	hashPattern := regexp.MustCompile(`/[0-9a-f]{32,}`)
	path = hashPattern.ReplaceAllString(path, "/{hash}")

	// Simplify query params to just indicate presence
	if parsed.RawQuery != "" {
		path += "?params"
	}

	return parsed.Host + path
}

// urlScore calculates a priority score for a URL
// Higher score = more interesting for vulnerability testing
func (sf *SmartFilter) urlScore(rawURL string) int {
	score := 0
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}

	urlLower := strings.ToLower(rawURL)
	pathLower := strings.ToLower(parsed.Path)

	// HIGHEST PRIORITY: Sensitive files (critical for bug bounty)
	sensitiveExtensions := []string{".env", ".sql", ".db", ".bak", ".backup", ".old", ".config", ".conf", ".key", ".pem", ".log"}
	for _, ext := range sensitiveExtensions {
		if strings.Contains(urlLower, ext) {
			score += 500 // Very high priority
			break
		}
	}

	// HIGH PRIORITY: Critical paths
	criticalPaths := []string{".git", "backup", "debug", "console", "phpinfo", "test", "dev"}
	for _, path := range criticalPaths {
		if strings.Contains(urlLower, path) {
			score += 200
			break
		}
	}

	// URLs with query parameters are more interesting
	if parsed.RawQuery != "" {
		score += 100
		// More parameters = higher score
		params := strings.Count(parsed.RawQuery, "&") + 1
		score += params * 10
	}

	// API endpoints are interesting
	if strings.Contains(parsed.Path, "/api/") {
		score += 50
	}

	// Authentication/session related endpoints
	authKeywords := []string{"login", "auth", "session", "user", "account", "admin", "password", "reset"}
	for _, keyword := range authKeywords {
		if strings.Contains(pathLower, keyword) {
			score += 30
			break
		}
	}

	// Data manipulation endpoints
	dataKeywords := []string{"edit", "update", "delete", "create", "upload", "download", "search", "filter"}
	for _, keyword := range dataKeywords {
		if strings.Contains(pathLower, keyword) {
			score += 20
			break
		}
	}

	// JavaScript files (for JS analysis)
	if strings.HasSuffix(pathLower, ".js") && !strings.Contains(pathLower, ".min.js") {
		score += 40 // Regular JS files are important
	}

	// Shorter paths are generally more important endpoints
	pathDepth := strings.Count(parsed.Path, "/")
	score += (10 - pathDepth) // Reward shallower paths

	return score
}

// prioritizeParameterized sorts URLs to put parameterized ones first
func (sf *SmartFilter) prioritizeParameterized(urls []string) []string {
	sort.Slice(urls, func(i, j int) bool {
		return sf.urlScore(urls[i]) > sf.urlScore(urls[j])
	})
	return urls
}

// removeDuplicates removes exact duplicate URLs
func removeDuplicates(urls []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, u := range urls {
		if !seen[u] {
			seen[u] = true
			result = append(result, u)
		}
	}

	return result
}
