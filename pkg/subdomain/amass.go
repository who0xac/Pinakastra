package subdomain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

// runAmass executes Amass subdomain enumeration
func (p *PassiveEnumerator) runAmass(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{
		ToolName:   "Amass",
		Subdomains: []string{},
	}

	if err := checkToolExists("amass"); err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	// Show warning that Amass may take time due to active scanning
	terminal.PrintToolStartingWithWarning("Amass", "may take time - active scanning")

	outputFile := filepath.Join(p.OutputDir, "amass.txt")

	args := []string{
		"enum",
		"-active",
		"-d", p.Domain,
	}

	if p.AmassConfig != "" && fileExists(p.AmassConfig) {
		args = append(args, "-config", p.AmassConfig)
	}

	if p.Resolvers != "" && fileExists(p.Resolvers) {
		args = append(args, "-rf", p.Resolvers)
	}

	args = append(args, "-o", outputFile)

	cmd := exec.CommandContext(ctx, "amass", args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Error = fmt.Errorf("amass failed: %v - %s", err, string(output))
		result.Duration = time.Since(start)
		return result
	}

	subdomains, err := readLinesFromFile(outputFile)
	if err != nil {
		result.Error = fmt.Errorf("failed to read amass output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Subdomains = subdomains
	result.Duration = time.Since(start)
	return result
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
