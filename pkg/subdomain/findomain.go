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

	terminal.PrintToolStarting("Findomain")

	cmd := exec.CommandContext(ctx, "findomain", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
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
}
