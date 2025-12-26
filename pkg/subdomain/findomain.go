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

	cmd := exec.CommandContext(ctx, "findomain", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("findomain failed to start: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Print initial status line
	fmt.Printf("%s %s is running... ⠋ 0m 0s", terminal.Yellow("●"), terminal.Blue("Findomain"))

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
				result.Error = fmt.Errorf("findomain failed: %v - %s", err, stderr.String())
				result.Duration = time.Since(start)
				return result
			}

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

		case <-ticker.C:
			elapsed := time.Since(start)
			terminal.PrintToolRunning("Findomain", spinners[i%len(spinners)], elapsed, "")
			i++

		case <-ctx.Done():
			result.Error = fmt.Errorf("findomain cancelled")
			result.Duration = time.Since(start)
			return result
		}
	}
}
