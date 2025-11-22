package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Secretfinder struct {
	BaseTool
	config *config.Config
}

func NewSecretfinder(cfg *config.Config) *Secretfinder {
	return &Secretfinder{
		BaseTool: BaseTool{
			ToolName:  "secretfinder",
			ToolDesc:  "Find sensitive data in HTTP responses",
			ToolPhase: 8,
			Command:   "secretfinder",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (s *Secretfinder) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "secretfinder.txt")

	args := []string{
		"-i", "https://" + domain,
		"-o", "cli",
	}

	output, err := RunCommand(ctx, "secretfinder", args...)
	if err != nil {
		return "", fmt.Errorf("secretfinder failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
