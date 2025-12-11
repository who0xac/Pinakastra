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
		result.Error = fmt.Errorf("puredns not installed (optional)")
		result.Duration = time.Since(start)
		return result
	}

	if !fileExists(p.Wordlist) {
		result.Error = fmt.Errorf("wordlist not found: %s", p.Wordlist)
		result.Duration = time.Since(start)
		return result
	}

	// Count total lines in wordlist for progress tracking
	totalSubdomains, err := countFileLines(p.Wordlist)
	if err != nil {
		totalSubdomains = 0 // If we can't count, just proceed without progress
	}

	// Show warning that Puredns may take time due to brute forcing
	terminal.PrintToolStartingWithWarning("Puredns", "may take time - brute forcing")
	fmt.Println()

	outputFile := filepath.Join(p.OutputDir, "puredns.txt")
	args := []string{"bruteforce", p.Wordlist, p.Domain, "-w", outputFile}

	if p.Resolvers != "" && fileExists(p.Resolvers) {
		args = append(args, "-r", p.Resolvers)
	}

	args = append(args, "-t", "500")

	cmd := exec.CommandContext(ctx, "puredns", args...)

	// Create pipes to capture output
	stderr, err := cmd.StderrPipe()
	if err == nil {
		// Monitor stderr for progress if possible
		go func() {
			scanner := bufio.NewScanner(stderr)
			current := 0
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for scanner.Scan() {
				line := scanner.Text()
				// Puredns outputs progress info - try to extract it
				if strings.Contains(line, "Queried") || strings.Contains(line, "queries") {
					current++
					if totalSubdomains > 0 {
						select {
						case <-ticker.C:
							terminal.PrintToolProgress("Puredns", current, totalSubdomains)
						default:
						}
					}
				}
			}
		}()
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Error = fmt.Errorf("puredns failed (optional): %v - %s", err, string(output))
		result.Duration = time.Since(start)
		return result
	}

	// Clear the progress line
	fmt.Print("\r\033[K")

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
