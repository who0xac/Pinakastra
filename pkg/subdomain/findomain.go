package subdomain

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

func (p *PassiveEnumerator) runFindomain(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "Findomain", Subdomains: []string{}}

	if err := checkToolExists("findomain"); err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "findomain.txt")
	args := []string{"-t", p.Domain, "--quiet"}

	terminal.PrintToolStarting("Findomain")

	cmd := exec.CommandContext(ctx, "findomain", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start the command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("findomain failed to start: %v", err)
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
				result.Error = fmt.Errorf("findomain failed: %v - %s", err, stderr.String())
				result.Duration = time.Since(start)
				return result
			}
			goto finished
		case <-ticker.C:
			elapsed += time.Second
			terminal.PrintToolRunning("Findomain", elapsed)
		case <-ctx.Done():
			cmd.Process.Kill()
			result.Error = ctx.Err()
			result.Duration = time.Since(start)
			return result
		}
	}

finished:
	fmt.Print("\r\033[K") // Clear line

	output := stdout.String()
	subdomains := parseLinesFromString(output)

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		result.Error = fmt.Errorf("failed to save findomain output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Subdomains = subdomains
	result.Duration = time.Since(start)
	return result
}
