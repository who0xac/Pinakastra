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

	"github.com/who0xac/pinakastra/pkg/output/terminal"
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

	terminal.PrintToolStarting("Shodan")

	cmd := exec.CommandContext(ctx, "shodan", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start the command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("shodan failed to start: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	// Show animated progress while running
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Animate progress
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	elapsed := time.Duration(0)

	for {
		select {
		case err := <-done:
			fmt.Print("\r\033[K") // Clear line
			if err != nil {
				result.Error = fmt.Errorf("shodan failed (optional): %v - %s", err, stderr.String())
				result.Duration = time.Since(start)
				return result
			}
			goto finished
		case <-ticker.C:
			elapsed += time.Second
			terminal.PrintToolRunning("Shodan", elapsed)
		case <-ctx.Done():
			cmd.Process.Kill()
			result.Error = ctx.Err()
			result.Duration = time.Since(start)
			return result
		}
	}

finished:
	fmt.Print("\r\033[K") // Clear line

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
