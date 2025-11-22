package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Subfinder struct {
	BaseTool
	config *config.Config
}

func NewSubfinder(cfg *config.Config) *Subfinder {
	return &Subfinder{
		BaseTool: BaseTool{
			ToolName:  "subfinder",
			ToolDesc:  "Fast passive subdomain enumeration tool",
			ToolPhase: 1, // Subdomain Enumeration
			Command:   "subfinder",
			Timeout:   5 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (s *Subfinder) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "subfinder.txt")

	args := []string{
		"-d", domain,
		"-o", outputFile,
		"-silent",
	}

	// Add API keys if available
	if cfg.APIKeys.Chaos != "" {
		args = append(args, "-pc", cfg.APIKeys.Chaos)
	}

	output, err := RunCommand(ctx, "subfinder", args...)
	if err != nil {
		return "", fmt.Errorf("subfinder failed: %w", err)
	}

	// Read the output file to get results
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil // Return command output even if file read fails
	}

	return string(data), nil
}
