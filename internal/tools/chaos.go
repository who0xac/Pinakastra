package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Chaos struct {
	BaseTool
	config *config.Config
}

func NewChaos(cfg *config.Config) *Chaos {
	return &Chaos{
		BaseTool: BaseTool{
			ToolName:  "chaos",
			ToolDesc:  "ProjectDiscovery's Chaos dataset API client",
			ToolPhase: 1,
			Command:   "chaos",
			Timeout:   5 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (c *Chaos) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "chaos.txt")

	args := []string{
		"-d", domain,
		"-o", outputFile,
		"-silent",
	}

	output, err := RunCommand(ctx, "chaos", args...)
	if err != nil {
		return "", fmt.Errorf("chaos failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
