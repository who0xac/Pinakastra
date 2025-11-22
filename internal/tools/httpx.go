package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Httpx struct {
	BaseTool
	config *config.Config
}

func NewHttpx(cfg *config.Config) *Httpx {
	return &Httpx{
		BaseTool: BaseTool{
			ToolName:  "httpx",
			ToolDesc:  "Fast HTTP probe tool",
			ToolPhase: 4, // HTTP Probing
			Command:   "httpx",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (h *Httpx) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.Timeout)
	defer cancel()

	// Input file from previous subdomain enumeration
	subdomainFile := filepath.Join(outputDir, "subfinder.txt")
	outputFile := filepath.Join(outputDir, "httpx.txt")

	// Check if subdomain file exists
	if _, err := os.Stat(subdomainFile); os.IsNotExist(err) {
		// If no subdomain file, probe the main domain
		args := []string{
			"-u", domain,
			"-o", outputFile,
			"-silent",
			"-status-code",
			"-title",
			"-tech-detect",
		}

		output, err := RunCommand(ctx, "httpx", args...)
		if err != nil {
			return "", fmt.Errorf("httpx failed: %w", err)
		}

		data, _ := os.ReadFile(outputFile)
		if data != nil {
			return string(data), nil
		}
		return output, nil
	}

	// Probe subdomains from file
	args := []string{
		"-l", subdomainFile,
		"-o", outputFile,
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
	}

	output, err := RunCommand(ctx, "httpx", args...)
	if err != nil {
		return "", fmt.Errorf("httpx failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
