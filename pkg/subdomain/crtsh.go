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

	// Check if crtsh tool is available
	if err := checkToolExists("crtsh"); err != nil {
		result.Error = fmt.Errorf("crtsh not installed - install from github.com/cemulus/crtsh")
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "crtsh.txt")

	// Run crtsh command
	args := []string{"-d", p.Domain, "-r"}

	cmd := exec.CommandContext(ctx, "crtsh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("crtsh failed to start: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Print initial status line
	fmt.Printf("%s %s is running... ⠋ 0m 0s", terminal.Yellow("●"), terminal.Blue("crt.sh"))

	// Animation loop
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	i := 0

	for {
		select {
		case err := <-done:
			if err != nil {
				result.Error = fmt.Errorf("crt.sh failed: %v", err)
				result.Duration = time.Since(start)
				return result
			}

			output := stdout.Bytes()

			// Save raw output to file
			if err := os.WriteFile(outputFile, output, 0644); err != nil {
				result.Error = fmt.Errorf("failed to save crt.sh output: %v", err)
				result.Duration = time.Since(start)
				return result
			}

			// Parse output (one subdomain per line)
			subdomains := parseLinesFromString(string(output))

			result.Subdomains = subdomains
			result.Duration = time.Since(start)
			return result

		case <-ticker.C:
			elapsed := time.Since(start)
			terminal.PrintToolRunning("crt.sh", spinners[i%len(spinners)], elapsed, "")
			i++

		case <-ctx.Done():
			result.Error = fmt.Errorf("crtsh cancelled")
			result.Duration = time.Since(start)
			return result
		}
	}
}
