package urldiscovery

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
		"-u", k.InputFile,
		"-d", "5",
		"-kf", "all",
		"-jc",
		"-fx",
		"-xhr",
		"-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif",
		"-o", outputFile,
		"-rl", "150",
		"-c", "10",
		"-silent", // Silent mode
	}

	cmd := exec.CommandContext(ctx, "katana", args...)

	// Capture stderr
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start katana: %v", err)
	}

	// Monitor stderr
	var stderrOutput strings.Builder
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			stderrOutput.WriteString(scanner.Text() + "\n")
		}
	}()

	// Spinner animation
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	i := 0
	for {
		select {
		case err := <-done:
			if err != nil {
				terminal.PrintToolFailed("Katana", err, time.Since(start))
				os.Create(outputFile)
				return &KatanaResult{TotalURLs: 0}, nil
			}

			// Count URLs
			count := 0
			if c, err := countLines(outputFile); err == nil {
				count = c
			}

			terminal.PrintToolCompleted("Katana", count, time.Since(start))
			return &KatanaResult{
				TotalURLs: count,
				Duration:  time.Since(start),
			}, nil

		case <-ticker.C:
			elapsed := time.Since(start)
			// Count current URLs in file
			count := 0
			if c, err := countLines(outputFile); err == nil {
				count = c
			}
			terminal.PrintToolRunning("Katana", spinners[i%len(spinners)], elapsed, fmt.Sprintf("%d URLs", count))
			i++

		case <-ctx.Done():
			return nil, fmt.Errorf("katana cancelled")
		}
	}
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
