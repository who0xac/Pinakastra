package subdomain

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

func (p *PassiveEnumerator) runPuredns(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "Puredns", Subdomains: []string{}}

	if err := checkToolExists("puredns"); err != nil {
		result.Error = fmt.Errorf("puredns not installed - run: go install github.com/d3mondev/puredns/v2@latest")
		result.Duration = time.Since(start)
		return result
	}

	if !fileExists(p.Wordlist) {
		result.Error = fmt.Errorf("wordlist not found: %s", p.Wordlist)
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "puredns.txt")
	args := []string{"bruteforce", p.Wordlist, p.Domain, "-w", outputFile}

	if p.Resolvers != "" && fileExists(p.Resolvers) {
		args = append(args, "-r", p.Resolvers)
	}

	args = append(args, "-t", "500")

	cmd := exec.CommandContext(ctx, "puredns", args...)

	// Capture stderr to show progress
	stderr, err := cmd.StderrPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stderr pipe: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Start command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("puredns failed to start: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Print initial message
	fmt.Printf("\n%s %s is running (may take time)...\n", terminal.Yellow("●"), terminal.Blue("Puredns"))

	// Read stderr in goroutine and capture interesting lines
	progressLines := []string{}
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()

			// Capture only the summary lines (not the progress bars)
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				// Filter: Only keep non-progress-bar lines
				if !strings.Contains(line, "ETA") &&
				   !strings.Contains(line, "rate:") &&
				   !strings.HasPrefix(trimmed, "|") &&
				   !strings.HasPrefix(trimmed, "[ETA") {
					// Keep lines like "Resolving domains...", "Found X valid domains", etc.
					if strings.Contains(line, "Resolving domains") ||
					   strings.Contains(line, "Detecting wildcard") ||
					   strings.Contains(line, "Validating domains") ||
					   strings.Contains(line, "Found") {
						progressLines = append(progressLines, trimmed)
					}
				}
			}
		}
		done <- cmd.Wait()
	}()

	// Wait for completion
	err = <-done

	// Print captured progress lines
	for _, line := range progressLines {
		fmt.Printf("   %s\n", terminal.Gray(line))
	}

	if err != nil {
		result.Error = fmt.Errorf("puredns failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	subdomains, err := readLinesFromFile(outputFile)
	if err != nil {
		result.Error = fmt.Errorf("failed to read puredns output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Subdomains = subdomains
	result.Duration = time.Since(start)
	return result
}

// countFileLines counts the number of non-empty, non-comment lines in a file
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
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return count, nil
}
