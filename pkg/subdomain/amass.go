package subdomain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

// runAmass executes Amass subdomain enumeration
func (p *PassiveEnumerator) runAmass(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{
		ToolName:   "Amass",
		Subdomains: []string{},
	}

	if err := checkToolExists("amass"); err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	// Show warning that Amass may take time due to active scanning
	terminal.PrintToolStartingWithWarning("Amass", "may take time - active scanning")

	outputFile := filepath.Join(p.OutputDir, "amass.txt")

	args := []string{
		"enum",
		"-active",
		"-d", p.Domain,
	}

	if p.AmassConfig != "" && fileExists(p.AmassConfig) {
		args = append(args, "-config", p.AmassConfig)
	}

	if p.Resolvers != "" && fileExists(p.Resolvers) {
		args = append(args, "-rf", p.Resolvers)
	}

	args = append(args, "-o", outputFile)

	cmd := exec.CommandContext(ctx, "amass", args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")

	// Start the command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("amass failed to start: %v", err)
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
				result.Error = fmt.Errorf("amass failed: %v", err)
				result.Duration = time.Since(start)
				return result
			}
			goto finished
		case <-ticker.C:
			elapsed += time.Second
			terminal.PrintToolRunning("Amass", elapsed)
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
		result.Error = fmt.Errorf("failed to read amass output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Subdomains = subdomains
	result.Duration = time.Since(start)
	return result
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
