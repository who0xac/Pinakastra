package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// VersionChecker checks for latest versions of services
type VersionChecker struct {
	client *http.Client
}

// NewVersionChecker creates a new version checker
func NewVersionChecker() *VersionChecker {
	return &VersionChecker{
		client: &http.Client{
			Timeout: 5 * time.Second, // Increased to 5s for reliability
		},
	}
}

// GetLatestVersion retrieves the latest stable version for a service
func (v *VersionChecker) GetLatestVersion(ctx context.Context, service, currentVersion string) (string, bool, error) {
	// Add timeout to entire operation
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	service = strings.ToLower(service)

	// Normalize service names
	if strings.Contains(service, "openssh") || strings.Contains(service, "ssh") {
		return v.getOpenSSHVersion(timeoutCtx, currentVersion)
	}

	if strings.Contains(service, "apache") && strings.Contains(service, "httpd") {
		return v.getApacheVersion(timeoutCtx, currentVersion)
	}

	if strings.Contains(service, "nginx") {
		return v.getNginxVersion(timeoutCtx, currentVersion)
	}

	if strings.Contains(service, "mysql") {
		return v.getMySQLVersion(timeoutCtx, currentVersion)
	}

	if strings.Contains(service, "mariadb") {
		return v.getMariaDBVersion(timeoutCtx, currentVersion)
	}

	if strings.Contains(service, "postgresql") || strings.Contains(service, "postgres") {
		return v.getPostgreSQLVersion(timeoutCtx, currentVersion)
	}

	if strings.Contains(service, "redis") {
		return v.getRedisVersion(timeoutCtx, currentVersion)
	}

	if strings.Contains(service, "mongodb") {
		return v.getMongoDBVersion(timeoutCtx, currentVersion)
	}

	// Unknown service - return empty
	return "", false, nil
}

// getOpenSSHVersion gets latest OpenSSH version
func (v *VersionChecker) getOpenSSHVersion(ctx context.Context, current string) (string, bool, error) {
	// OpenSSH releases page
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.openssh.com/releasenotes.html", nil)
	if err != nil {
		return "", false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	// Find version in format: OpenSSH 9.9 released
	re := regexp.MustCompile(`OpenSSH\s+(\d+\.\d+(?:p\d+)?)`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	if len(matches) > 0 {
		latest := matches[0][1]
		outdated := v.isVersionOutdated(current, latest)
		return latest, outdated, nil
	}

	return "", false, nil
}

// getApacheVersion gets latest Apache httpd version
func (v *VersionChecker) getApacheVersion(ctx context.Context, current string) (string, bool, error) {
	// Apache download page
	req, err := http.NewRequestWithContext(ctx, "GET", "https://httpd.apache.org/download.cgi", nil)
	if err != nil {
		return "", false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	// Find version in format: Apache HTTP Server 2.4.62
	re := regexp.MustCompile(`Apache HTTP Server\s+(\d+\.\d+\.\d+)`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	if len(matches) > 0 {
		latest := matches[0][1]
		outdated := v.isVersionOutdated(current, latest)
		return latest, outdated, nil
	}

	return "", false, nil
}

// getNginxVersion gets latest Nginx version
func (v *VersionChecker) getNginxVersion(ctx context.Context, current string) (string, bool, error) {
	// Nginx news page
	req, err := http.NewRequestWithContext(ctx, "GET", "https://nginx.org/", nil)
	if err != nil {
		return "", false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	// Find mainline version: nginx-1.27.3
	re := regexp.MustCompile(`nginx-(\d+\.\d+\.\d+)`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	if len(matches) > 0 {
		latest := matches[0][1]
		outdated := v.isVersionOutdated(current, latest)
		return latest, outdated, nil
	}

	return "", false, nil
}

// getMySQLVersion gets latest MySQL version from GitHub API
func (v *VersionChecker) getMySQLVersion(ctx context.Context, current string) (string, bool, error) {
	// Use MySQL's official download page
	req, err := http.NewRequestWithContext(ctx, "GET", "https://dev.mysql.com/downloads/mysql/", nil)
	if err != nil {
		return "", false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	// Find version: MySQL Community Server 8.x.x or 9.x.x
	re := regexp.MustCompile(`MySQL Community Server\s+(\d+\.\d+\.\d+)`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	if len(matches) > 0 {
		latest := matches[0][1]
		outdated := v.isVersionOutdated(current, latest)
		return latest, outdated, nil
	}

	return "", false, nil
}

// getMariaDBVersion gets latest MariaDB version
func (v *VersionChecker) getMariaDBVersion(ctx context.Context, current string) (string, bool, error) {
	// MariaDB downloads page
	req, err := http.NewRequestWithContext(ctx, "GET", "https://mariadb.org/download/", nil)
	if err != nil {
		return "", false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	// Find version
	re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	matches := re.FindAllStringSubmatch(string(body), 5)

	if len(matches) > 0 {
		latest := matches[0][1]
		outdated := v.isVersionOutdated(current, latest)
		return latest, outdated, nil
	}

	return "", false, nil
}

// getPostgreSQLVersion gets latest PostgreSQL version
func (v *VersionChecker) getPostgreSQLVersion(ctx context.Context, current string) (string, bool, error) {
	// PostgreSQL download page
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.postgresql.org/versions/", nil)
	if err != nil {
		return "", false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	// Find latest version
	re := regexp.MustCompile(`PostgreSQL\s+(\d+\.\d+)`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	if len(matches) > 0 {
		latest := matches[0][1]
		outdated := v.isVersionOutdated(current, latest)
		return latest, outdated, nil
	}

	return "", false, nil
}

// getRedisVersion gets latest Redis version from GitHub API
func (v *VersionChecker) getRedisVersion(ctx context.Context, current string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/redis/redis/releases/latest", nil)
	if err != nil {
		return "", false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", false, err
	}

	// Tag format: "7.2.4"
	latest := strings.TrimPrefix(release.TagName, "v")
	outdated := v.isVersionOutdated(current, latest)
	return latest, outdated, nil
}

// getMongoDBVersion gets latest MongoDB version
func (v *VersionChecker) getMongoDBVersion(ctx context.Context, current string) (string, bool, error) {
	// MongoDB downloads page
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.mongodb.com/try/download/community", nil)
	if err != nil {
		return "", false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	// Find version
	re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	matches := re.FindAllStringSubmatch(string(body), 5)

	if len(matches) > 0 {
		latest := matches[0][1]
		outdated := v.isVersionOutdated(current, latest)
		return latest, outdated, nil
	}

	return "", false, nil
}

// isVersionOutdated compares current version with latest version
func (v *VersionChecker) isVersionOutdated(current, latest string) bool {
	if current == "" || latest == "" {
		return false
	}

	// Remove common prefixes
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	// Extract version numbers
	currentParts := v.extractVersionNumbers(current)
	latestParts := v.extractVersionNumbers(latest)

	// Compare major.minor.patch
	for i := 0; i < len(currentParts) && i < len(latestParts); i++ {
		if currentParts[i] < latestParts[i] {
			return true
		}
		if currentParts[i] > latestParts[i] {
			return false
		}
	}

	// If all parts are equal, check if current has fewer parts (e.g., 7.4 vs 9.9)
	return len(currentParts) < len(latestParts)
}

// extractVersionNumbers extracts numeric parts from version string
func (v *VersionChecker) extractVersionNumbers(version string) []int {
	re := regexp.MustCompile(`\d+`)
	matches := re.FindAllString(version, -1)

	var numbers []int
	for _, match := range matches {
		var num int
		fmt.Sscanf(match, "%d", &num)
		numbers = append(numbers, num)
	}

	return numbers
}
