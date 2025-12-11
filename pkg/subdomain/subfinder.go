package subdomain

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
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
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Error = fmt.Errorf("subfinder failed: %v - %s", err, string(output))
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
}
