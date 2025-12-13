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

func (p *PassiveEnumerator) runCrtsh(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "crt.sh", Subdomains: []string{}}

	if err := checkToolExists("crtsh"); err != nil {
		result.Error = fmt.Errorf("crtsh not installed (optional)")
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "crtsh.txt")
	args := []string{"-d", p.Domain, "-r"}

	terminal.PrintToolStarting("crt.sh")

	cmd := exec.CommandContext(ctx, "crtsh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start the command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("crtsh failed to start: %v", err)
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
				result.Error = fmt.Errorf("crtsh failed (optional): %v", err)
				result.Duration = time.Since(start)
				return result
			}
			goto finished
		case <-ticker.C:
			elapsed += time.Second
			terminal.PrintToolRunning("crt.sh", elapsed)
		case <-ctx.Done():
			cmd.Process.Kill()
			result.Error = ctx.Err()
			result.Duration = time.Since(start)
			return result
		}
	}

finished:
	fmt.Print("\r\033[K") // Clear line

	output := stdout.Bytes()

	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		result.Error = fmt.Errorf("failed to save crtsh output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	subdomains := parseLinesFromString(string(output))
	result.Subdomains = subdomains
	result.Duration = time.Since(start)
	return result
}
