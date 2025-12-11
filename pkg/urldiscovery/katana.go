package urldiscovery

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"pinakastra/pkg/output/terminal"
)

// KatanaRunner handles Katana URL crawling
type KatanaRunner struct {
	InputFile string
	OutputDir string
}

// KatanaResult contains crawling results
type KatanaResult struct {
	TotalURLs int
	Duration  time.Duration
}

// NewKatanaRunner creates a new Katana runner
func NewKatanaRunner(inputFile, outputDir string) *KatanaRunner {
	return &KatanaRunner{
		InputFile: inputFile,
		OutputDir: outputDir,
	}
}

// Run executes Katana crawling
func (k *KatanaRunner) Run(ctx context.Context) (*KatanaResult, error) {
	outputFile := filepath.Join(k.OutputDir, "katana_urls.txt")

	// Check if Katana is installed
	if err := checkToolExists("katana"); err != nil {
		terminal.PrintToolSkipped("Katana", "not installed")
		// Create empty file to avoid errors in merge step
		os.Create(outputFile)
		return &KatanaResult{TotalURLs: 0}, nil
	}

	// Verify input file exists
	if _, err := os.Stat(k.InputFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("input file not found: %s", k.InputFile)
	}

	terminal.PrintToolStarting("Katana")
	start := time.Now()

	// Katana command
	args := []string{
		"-list", k.InputFile,
		"-d", "5",                              // Depth = 5
		"-jc",                                  // JavaScript crawling
		"-kf", "robotstxt,sitemapxml",          // Known files
		"-ef", "woff,woff2,ttf,eot,svg,png,jpg,jpeg,gif,ico,css", // Exclude extensions
		"-c", "50",                             // Concurrency
		"-p", "10",                             // Parallelism
		"-timeout", "10",                       // Timeout
		"-retry", "2",                          // Retry
		"-rl", "100",                           // Rate limit
		"-o", outputFile,
	}

	cmd := exec.CommandContext(ctx, "katana", args...)

	// Capture output for monitoring
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start katana: %v", err)
	}

	// Monitor output
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			// Katana outputs URLs directly, no need to parse
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			// Monitor for errors if needed
		}
	}()

	wg.Wait()

	// Wait for command to finish
	if err := cmd.Wait(); err != nil {
		// Katana might fail, but we continue
		terminal.PrintToolFailed("Katana", err)
		os.Create(outputFile) // Create empty file
		return &KatanaResult{TotalURLs: 0}, nil
	}

	// Count URLs
	result := &KatanaResult{
		Duration: time.Since(start),
	}

	if count, err := countLines(outputFile); err == nil {
		result.TotalURLs = count
	}

	terminal.PrintToolCompleted("Katana", result.TotalURLs, result.Duration)

	return result, nil
}

// countLines counts lines in a file
func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}

	return count, scanner.Err()
}

// checkToolExists verifies if a tool is installed
func checkToolExists(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("%s not found in PATH", toolName)
	}
	return nil
}
