package httpprobe

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

// HTTPProber handles HTTP probing with httpx
type HTTPProber struct {
	InputFile  string
	OutputDir  string
	Proxy      string
	Threads    int
	RateLimit  int
}

// ProbeResult contains the results of HTTP probing
type ProbeResult struct {
	LiveURLs       []string
	TotalProbed    int
	LiveCount      int
	HTTPXResults   string
	Duration       time.Duration
	Error          error
}

// NewHTTPProber creates a new HTTP prober instance
func NewHTTPProber(inputFile, outputDir string) *HTTPProber {
	return &HTTPProber{
		InputFile:  inputFile,
		OutputDir:  outputDir,
		Threads:    150,
		RateLimit:  50,
	}
}

// Run executes HTTP probing
func (h *HTTPProber) Run(ctx context.Context) (*ProbeResult, error) {
	start := time.Now()
	result := &ProbeResult{}

	terminal.PrintSectionHeader("HTTP PROBING")

	// Check if httpx is installed
	if err := checkToolExists("httpx"); err != nil {
		return nil, fmt.Errorf("httpx not installed: %v", err)
	}

	// Verify input file exists
	if !fileExists(h.InputFile) {
		return nil, fmt.Errorf("input file not found: %s", h.InputFile)
	}

	// Count total subdomains to probe
	totalSubdomains, err := countFileLines(h.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to count input lines: %v", err)
	}
	result.TotalProbed = totalSubdomains

	terminal.PrintToolStarting("HTTPX", fmt.Sprintf("probing %d subdomains", totalSubdomains))

	// Prepare output files
	httpxResultsFile := filepath.Join(h.OutputDir, "httpx_results.txt")
	liveURLsFile := filepath.Join(h.OutputDir, "live_urls.txt")

	// Build httpx command
	args := []string{
		"-l", h.InputFile,
		"-sc",                          // Show status code
		"-mc", "200,301,302,403,500",   // Match codes
		"-fr",                          // Follow redirects
		"-td",                          // Tech detection
		"-location",                    // Show redirect location
		"-o", httpxResultsFile,         // Output file
		"-threads", fmt.Sprintf("%d", h.Threads),
		"-rate-limit", fmt.Sprintf("%d", h.RateLimit),
		"-timeout", "10",               // Timeout in seconds
		"-retries", "2",                // Retry failed requests
		"-silent",                      // Silent mode
	}

	if h.Proxy != "" {
		args = append(args, "-proxy", h.Proxy)
	}

	cmd := exec.CommandContext(ctx, "httpx", args...)

	// Capture stdout for live progress
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start httpx: %v", err)
	}

	// Create live_urls.txt file
	liveURLsFileHandle, err := os.Create(liveURLsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create live URLs file: %v", err)
	}
	defer liveURLsFileHandle.Close()

	// Monitor stdout and extract URLs
	liveURLs := []string{}
	scanner := bufio.NewScanner(stdout)
	currentCount := 0
	liveCount := 0

	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			currentCount++

			// Extract URL (first field before space)
			parts := strings.Fields(line)
			if len(parts) > 0 {
				url := parts[0]
				liveURLs = append(liveURLs, url)
				liveCount++

				// Write to live_urls.txt
				fmt.Fprintln(liveURLsFileHandle, url)

				// Update progress
				terminal.PrintToolProgress("HTTPX", currentCount, totalSubdomains)
			}
		}
	}()

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		// HTTPX can fail on some URLs but still produce results
		// So we only return error if no results were found
		if liveCount == 0 {
			return nil, fmt.Errorf("httpx failed: %v", err)
		}
	}

	// Clear progress line
	fmt.Print("\r\033[K")

	result.LiveURLs = liveURLs
	result.LiveCount = liveCount
	result.HTTPXResults = httpxResultsFile
	result.Duration = time.Since(start)

	terminal.PrintToolCompleted("HTTPX", liveCount, result.Duration)

	// Print summary
	terminal.PrintHTTPProbeSummary(totalSubdomains, liveCount)

	return result, nil
}

// checkToolExists verifies if a tool is installed
func checkToolExists(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("%s not found in PATH", toolName)
	}
	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// countFileLines counts non-empty lines in a file
func countFileLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return count, nil
}
