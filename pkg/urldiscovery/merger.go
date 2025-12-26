package urldiscovery

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

// URLMerger handles merging and deduplication of URLs
type URLMerger struct {
	OutputDir string
}

// MergeResult contains merge results
type MergeResult struct {
	LiveURLs   int
	KatanaURLs int
	GAUURLs    int
	TotalURLs  int
	Duration   time.Duration
}

// NewURLMerger creates a new URL merger
func NewURLMerger(outputDir string) *URLMerger {
	return &URLMerger{
		OutputDir: outputDir,
	}
}

// Merge combines live URLs, Katana and GAU results, deduplicates and filters
func (m *URLMerger) Merge() (*MergeResult, error) {
	liveURLsFile := filepath.Join(m.OutputDir, "live_urls.txt")
	katanaFile := filepath.Join(m.OutputDir, "katana_urls.txt")
	gauFile := filepath.Join(m.OutputDir, "gau_urls.txt")
	outputFile := filepath.Join(m.OutputDir, "all_urls.txt")

	terminal.PrintPhaseStarting("Merging & Deduplicating URLs")
	start := time.Now()

	// Regex for valid HTTP/HTTPS URLs
	urlRegex := regexp.MustCompile(`^https?://`)

	// Regex for excluded extensions
	excludeRegex := regexp.MustCompile(`\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot)(\?|$)`)

	// Read and merge URLs
	seen := make(map[string]bool)
	var allURLs []string

	// First, add live URLs from httpx
	liveCount := 0
	if urls, err := readURLs(liveURLsFile); err == nil {
		liveCount = len(urls)
		for _, url := range urls {
			if isValidURL(url, urlRegex, excludeRegex) && !seen[url] {
				allURLs = append(allURLs, url)
				seen[url] = true
			}
		}
	}

	// Count Katana URLs
	katanaCount := 0
	if urls, err := readURLs(katanaFile); err == nil {
		katanaCount = len(urls)
		for _, url := range urls {
			if isValidURL(url, urlRegex, excludeRegex) && !seen[url] {
				allURLs = append(allURLs, url)
				seen[url] = true
			}
		}
	}

	// Count GAU URLs
	gauCount := 0
	if urls, err := readURLs(gauFile); err == nil {
		gauCount = len(urls)
		for _, url := range urls {
			if isValidURL(url, urlRegex, excludeRegex) && !seen[url] {
				allURLs = append(allURLs, url)
				seen[url] = true
			}
		}
	}

	// Write merged URLs (even if empty, create the file)
	output, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %v", err)
	}
	defer output.Close()

	for _, url := range allURLs {
		fmt.Fprintln(output, url)
	}

	result := &MergeResult{
		LiveURLs:   liveCount,
		KatanaURLs: katanaCount,
		GAUURLs:    gauCount,
		TotalURLs:  len(allURLs),
		Duration:   time.Since(start),
	}

	// Print summary
	if len(allURLs) == 0 {
		terminal.PrintWarning("No URLs found from any source")
	} else {
		terminal.PrintURLDiscoverySummary(liveCount, katanaCount, gauCount, len(allURLs))
	}

	return result, nil
}

// readURLs reads URLs from a file
func readURLs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// isValidURL checks if URL is valid and not excluded
func isValidURL(url string, urlRegex, excludeRegex *regexp.Regexp) bool {
	// Must start with http:// or https://
	if !urlRegex.MatchString(url) {
		return false
	}

	// Must not have excluded extensions
	if excludeRegex.MatchString(url) {
		return false
	}

	return true
}
