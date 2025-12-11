package subdomain

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

func (p *PassiveEnumerator) runChaos(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "Chaos", Subdomains: []string{}}

	if err := checkToolExists("chaos"); err != nil {
		result.Error = fmt.Errorf("chaos not installed (optional)")
		result.Duration = time.Since(start)
		return result
	}

	if p.ChaosAPIKey == "" {
		result.Error = fmt.Errorf("chaos API key not provided (optional)")
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "chaos.txt")
	args := []string{"-key", p.ChaosAPIKey, "-d", p.Domain, "-o", outputFile, "-silent"}

	cmd := exec.CommandContext(ctx, "chaos", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Error = fmt.Errorf("chaos failed (optional): %v - %s", err, string(output))
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
}
