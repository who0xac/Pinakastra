package subdomain

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
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
	output, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() == nil {
		result.Error = fmt.Errorf("sublist3r failed: %v - %s", err, string(output))
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
}
