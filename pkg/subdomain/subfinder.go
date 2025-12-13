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

	terminal.PrintToolStarting("Subfinder")

	cmd := exec.CommandContext(ctx, "subfinder", args...)

	if err := cmd.Run(); err != nil {
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
}
