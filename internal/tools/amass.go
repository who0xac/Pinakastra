package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Amass struct {
	BaseTool
	config *config.Config
}

func NewAmass(cfg *config.Config) *Amass {
	return &Amass{
		BaseTool: BaseTool{
			ToolName:  "amass",
			ToolDesc:  "In-depth subdomain enumeration tool",
			ToolPhase: 1, // Subdomain Enumeration
			Command:   "amass",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (a *Amass) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "amass.txt")

	args := []string{
		"enum",
		"-d", domain,
		"-o", outputFile,
		"-passive",
	}

	// Add config file if it exists
	if cfg.Paths.AmassConfig != "" {
		if _, err := os.Stat(cfg.Paths.AmassConfig); err == nil {
			args = append(args, "-config", cfg.Paths.AmassConfig)
		}
	}

	output, err := RunCommand(ctx, "amass", args...)
	if err != nil {
		return "", fmt.Errorf("amass failed: %w", err)
	}

	// Read the output file to get results
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
