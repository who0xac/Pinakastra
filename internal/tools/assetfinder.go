package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Assetfinder struct {
	BaseTool
	config *config.Config
}

func NewAssetfinder(cfg *config.Config) *Assetfinder {
	return &Assetfinder{
		BaseTool: BaseTool{
			ToolName:  "assetfinder",
			ToolDesc:  "Find domains and subdomains",
			ToolPhase: 1,
			Command:   "assetfinder",
			Timeout:   5 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (a *Assetfinder) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "assetfinder.txt")

	args := []string{
		"--subs-only",
		domain,
	}

	output, err := RunCommand(ctx, "assetfinder", args...)
	if err != nil {
		return "", fmt.Errorf("assetfinder failed: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
