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

	cmd := exec.CommandContext(ctx, "subfinder", args...)

	// Start command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("subfinder failed to start: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Print initial status line
	fmt.Printf("%s %s is running... ⠋ 0m 0s", terminal.Yellow("●"), terminal.Blue("Subfinder"))

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
				result.Error = fmt.Errorf("subfinder failed: %v", err)
				result.Duration = time.Since(start)
				return result
			}

			subdomains, err := readLinesFromFile(outputFile)
			if err != nil {
				result.Error = fmt.Errorf("failed to read subfinder output: %v", err)
				result.Duration = time.Since(start)
				return result
			}

			result.Subdomains = subdomains
			result.Duration = time.Since(start)
			return result

		case <-ticker.C:
			elapsed := time.Since(start)
			terminal.PrintToolRunning("Subfinder", spinners[i%len(spinners)], elapsed, "")
			i++

		case <-ctx.Done():
			result.Error = fmt.Errorf("subfinder cancelled")
			result.Duration = time.Since(start)
			return result
		}
	}
}
