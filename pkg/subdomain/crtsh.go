package subdomain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func (p *PassiveEnumerator) runCrtsh(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "crt.sh", Subdomains: []string{}}

	if err := checkToolExists("crtsh"); err != nil {
		result.Error = fmt.Errorf("crtsh not installed (optional)")
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "crtsh.txt")
	args := []string{"-d", p.Domain, "-r"}

	cmd := exec.CommandContext(ctx, "crtsh", args...)
	output, err := cmd.CombinedOutput()

	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		result.Error = fmt.Errorf("failed to save crtsh output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	if err != nil {
		result.Error = fmt.Errorf("crtsh failed (optional): %v", err)
		result.Duration = time.Since(start)
		return result
	}

	subdomains := parseLinesFromString(string(output))
	result.Subdomains = subdomains
	result.Duration = time.Since(start)
	return result
}
