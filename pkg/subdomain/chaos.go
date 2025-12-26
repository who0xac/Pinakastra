package subdomain

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

func (p *PassiveEnumerator) runChaos(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "Chaos", Subdomains: []string{}}

	if err := checkToolExists("chaos"); err != nil {
		result.Error = fmt.Errorf("chaos not installed - install from github.com/projectdiscovery/chaos-client")
		result.Duration = time.Since(start)
		return result
	}

	if p.ChaosAPIKey == "" {
		result.Error = fmt.Errorf("chaos API key required!")
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "chaos.txt")
	args := []string{"-key", p.ChaosAPIKey, "-d", p.Domain, "-o", outputFile, "-silent"}

	cmd := exec.CommandContext(ctx, "chaos", args...)

	// Start command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("chaos failed to start: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Print initial status line
	fmt.Printf("%s %s is running... ⠋ 0m 0s", terminal.Yellow("●"), terminal.Blue("Chaos"))

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
				result.Error = fmt.Errorf("chaos failed: %v", err)
				result.Duration = time.Since(start)
				return result
			}

			subdomains, err := readLinesFromFile(outputFile)
			if err != nil {
				result.Error = fmt.Errorf("failed to read chaos output: %v", err)
				result.Duration = time.Since(start)
				return result
			}

			result.Subdomains = subdomains
			result.Duration = time.Since(start)
			return result

		case <-ticker.C:
			elapsed := time.Since(start)
			terminal.PrintToolRunning("Chaos", spinners[i%len(spinners)], elapsed, "")
			i++

		case <-ctx.Done():
			result.Error = fmt.Errorf("chaos cancelled")
			result.Duration = time.Since(start)
			return result
		}
	}
}
