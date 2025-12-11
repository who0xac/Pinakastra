package subdomain

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (p *PassiveEnumerator) runShodan(ctx context.Context) ToolResult {
	start := time.Now()
	result := ToolResult{ToolName: "Shodan", Subdomains: []string{}}

	if err := checkToolExists("shodan"); err != nil {
		result.Error = fmt.Errorf("shodan not installed (optional)")
		result.Duration = time.Since(start)
		return result
	}

	// Initialize Shodan with API key if provided
	if p.ShodanAPIKey != "" {
		initCmd := exec.CommandContext(ctx, "shodan", "init", p.ShodanAPIKey)
		if err := initCmd.Run(); err != nil {
			result.Error = fmt.Errorf("shodan init failed: %v (check API key)", err)
			result.Duration = time.Since(start)
			return result
		}
	} else {
		result.Error = fmt.Errorf("shodan API key not provided (optional)")
		result.Duration = time.Since(start)
		return result
	}

	outputFile := filepath.Join(p.OutputDir, "shodan.txt")
	query := fmt.Sprintf("ssl:%s", p.Domain)
	args := []string{"search", "--fields", "hostnames", query, "--limit", "0"}

	cmd := exec.CommandContext(ctx, "shodan", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		result.Error = fmt.Errorf("shodan failed (optional): %v - %s", err, stderr.String())
		result.Duration = time.Since(start)
		return result
	}

	output := stdout.String()
	lines := strings.Split(output, "\n")
	allSubdomains := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		hostnames := strings.Split(line, ";")
		for _, hostname := range hostnames {
			hostname = strings.TrimSpace(hostname)
			if hostname != "" {
				allSubdomains = append(allSubdomains, hostname)
			}
		}
	}

	if err := os.WriteFile(outputFile, []byte(strings.Join(allSubdomains, "\n")), 0644); err != nil {
		result.Error = fmt.Errorf("failed to save shodan output: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	result.Subdomains = allSubdomains
	result.Duration = time.Since(start)
	return result
}
