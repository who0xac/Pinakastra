package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Hakrawler struct {
	BaseTool
	config *config.Config
}

func NewHakrawler(cfg *config.Config) *Hakrawler {
	return &Hakrawler{
		BaseTool: BaseTool{
			ToolName:  "hakrawler",
			ToolDesc:  "Fast web crawler",
			ToolPhase: 5,
			Command:   "hakrawler",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (h *Hakrawler) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), h.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "hakrawler.txt")

	args := []string{
		"-url", "https://" + domain,
		"-depth", "2",
	}

	output, err := RunCommand(ctx, "hakrawler", args...)
	if err != nil {
		return "", fmt.Errorf("hakrawler failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
