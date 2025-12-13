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

// GAURunner handles GAU historical URL fetching
type GAURunner struct {
	InputFile string
	OutputDir string
}

// GAUResult contains fetching results
type GAUResult struct {
	TotalURLs int
	Duration  time.Duration
}

// NewGAURunner creates a new GAU runner
func NewGAURunner(inputFile, outputDir string) *GAURunner {
	return &GAURunner{
		InputFile: inputFile,
		OutputDir: outputDir,
	}
}

// Run executes GAU historical URL fetching
func (g *GAURunner) Run(ctx context.Context) (*GAUResult, error) {
	outputFile := filepath.Join(g.OutputDir, "gau_urls.txt")

	// Check if GAU is installed
	if err := checkToolExists("gau"); err != nil {
		terminal.PrintToolSkipped("GAU", "not installed")
		// Create empty file to avoid errors in merge step
		os.Create(outputFile)
		return &GAUResult{TotalURLs: 0}, nil
	}

	// Extract hostnames from live_urls.txt for GAU
	hostnamesFile := filepath.Join(g.OutputDir, "live_hostnames_for_gau.txt")
	if err := g.extractHostnames(g.InputFile, hostnamesFile); err != nil {
		return nil, fmt.Errorf("failed to extract hostnames: %v", err)
	}

	terminal.PrintToolStarting("GAU")
	start := time.Now()

	// GAU command - reads from stdin
	args := []string{
		"-b", "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot", // Blacklist extensions
		"-providers", "wayback,commoncrawl,otx,urlscan",         // Data sources
		"-t", "5",                                               // Threads
		"-o", outputFile,
	}

	cmd := exec.CommandContext(ctx, "gau", args...)

	// Read hostnames file and pipe to GAU stdin
	hostnames, err := os.ReadFile(hostnamesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read hostnames: %v", err)
	}

	// Set stdin
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start gau: %v", err)
	}

	// Write hostnames to stdin
	go func() {
		defer stdin.Close()
		stdin.Write(hostnames)
	}()

	// Wait for command to finish
	if err := cmd.Wait(); err != nil {
		// GAU might fail, but we continue
		terminal.PrintToolFailed("GAU", err)
		os.Create(outputFile) // Create empty file
		return &GAUResult{TotalURLs: 0}, nil
	}

	// Count URLs
	result := &GAUResult{
		Duration: time.Since(start),
	}

	if count, err := countLines(outputFile); err == nil {
		result.TotalURLs = count
	}

	terminal.PrintToolCompleted("GAU", result.TotalURLs, result.Duration)

	return result, nil
}

// extractHostnames extracts hostnames from URLs (removes protocol and path)
func (g *GAURunner) extractHostnames(inputFile, outputFile string) error {
	input, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer output.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(input)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Remove protocol
		hostname := strings.TrimPrefix(line, "http://")
		hostname = strings.TrimPrefix(hostname, "https://")

		// Remove path and everything after first /
		if idx := strings.Index(hostname, "/"); idx != -1 {
			hostname = hostname[:idx]
		}

		// Remove port if present
		if idx := strings.Index(hostname, ":"); idx != -1 {
			hostname = hostname[:idx]
		}

		hostname = strings.TrimSpace(hostname)

		// Write unique hostnames
		if hostname != "" && !seen[hostname] {
			fmt.Fprintln(output, hostname)
			seen[hostname] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
