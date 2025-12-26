package subdomain

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

func (p *PassiveEnumerator) runSublist3r(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "Sublist3r", Subdomains: []string{}}

	if err := checkToolExists("sublist3r"); err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "sublist3r.txt")
	args := []string{"-d", p.Domain, "-e", "baidu,yahoo,google,bing,ask,netcraft,threatcrowd,ssl,passivedns", "-o", outputFile}

	cmd := exec.CommandContext(ctx, "sublist3r", args...)

	// Start command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("sublist3r failed to start: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Print initial status line
	fmt.Printf("%s %s is running... ⠋ 0m 0s", terminal.Yellow("●"), terminal.Blue("Sublist3r"))

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
				result.Error = fmt.Errorf("sublist3r failed: %v", err)
				result.Duration = time.Since(start)
				return result
			}

			subdomains, err := readLinesFromFile(outputFile)
			if err != nil {
				result.Error = fmt.Errorf("failed to read sublist3r output: %v", err)
				result.Duration = time.Since(start)
				return result
			}

			result.Subdomains = subdomains
			result.Duration = time.Since(start)
			return result

		case <-ticker.C:
			elapsed := time.Since(start)
			terminal.PrintToolRunning("Sublist3r", spinners[i%len(spinners)], elapsed, "")
			i++

		case <-ctx.Done():
			result.Error = fmt.Errorf("sublist3r cancelled")
			result.Duration = time.Since(start)
			return result
		}
	}
}
