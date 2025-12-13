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

	terminal.PrintToolStarting("crt.sh")

	cmd := exec.CommandContext(ctx, "crtsh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		result.Error = fmt.Errorf("crtsh failed (optional): %v", err)
		result.Duration = time.Since(start)
		return result
	}

	output := stdout.Bytes()

	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		result.Error = fmt.Errorf("failed to save crtsh output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	subdomains := parseLinesFromString(string(output))
	result.Subdomains = subdomains
	result.Duration = time.Since(start)
	return result
}
