package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Shodan struct {
	BaseTool
	config *config.Config
}

func NewShodan(cfg *config.Config) *Shodan {
	return &Shodan{
		BaseTool: BaseTool{
			ToolName:  "shodan",
			ToolDesc:  "Search Shodan for information about domain",
			ToolPhase: 3,
			Command:   "shodan",
			Timeout:   5 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (s *Shodan) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "shodan.txt")

	if cfg.APIKeys.Shodan == "" {
		return "", fmt.Errorf("shodan API key not configured")
	}

	args := []string{
		"domain", domain,
	}

	output, err := RunCommand(ctx, "shodan", args...)
	if err != nil {
		return "", fmt.Errorf("shodan failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
