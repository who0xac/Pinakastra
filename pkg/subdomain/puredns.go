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

	if err := cmd.Run(); err != nil {
		result.Error = fmt.Errorf("puredns failed (optional): %v", err)
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
