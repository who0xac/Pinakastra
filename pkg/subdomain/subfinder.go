package subdomain

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

func (p *PassiveEnumerator) runSubfinder(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "Subfinder", Subdomains: []string{}}

	if err := checkToolExists("subfinder"); err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "subfinder.txt")
	args := []string{"-d", p.Domain, "-o", outputFile, "-rate-limit", "30", "-silent"}

	terminal.PrintToolStarting("Subfinder")

	cmd := exec.CommandContext(ctx, "subfinder", args...)

	// Start the command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("subfinder failed to start: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Show animated progress while running
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Animate progress
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	elapsed := time.Duration(0)

	for {
		select {
		case err := <-done:
			fmt.Print("\r\033[K") // Clear line
			if err != nil {
				result.Error = fmt.Errorf("subfinder failed: %v", err)
				result.Duration = time.Since(start)
				return result
			}
			goto finished
		case <-ticker.C:
			elapsed += time.Second
			terminal.PrintToolRunning("Subfinder", elapsed)
		case <-ctx.Done():
			cmd.Process.Kill()
			result.Error = ctx.Err()
			result.Duration = time.Since(start)
			return result
		}
	}

finished:
	fmt.Print("\r\033[K") // Clear line

	subdomains, err := readLinesFromFile(outputFile)
	if err != nil {
		result.Error = fmt.Errorf("failed to read subfinder output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Subdomains = subdomains
	result.Duration = time.Since(start)
	return result
}
