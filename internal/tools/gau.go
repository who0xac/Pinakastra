package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Gau struct {
	BaseTool
	config *config.Config
}

func NewGau(cfg *config.Config) *Gau {
	return &Gau{
		BaseTool: BaseTool{
			ToolName:  "gau",
			ToolDesc:  "Fetch known URLs from AlienVault's OTX, Wayback, Common Crawl",
			ToolPhase: 5,
			Command:   "gau",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (g *Gau) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), g.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "gau.txt")

	args := []string{
		"--subs",
		domain,
	}

	output, err := RunCommand(ctx, "gau", args...)
	if err != nil {
		return "", fmt.Errorf("gau failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
