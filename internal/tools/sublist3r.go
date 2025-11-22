package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Sublist3r struct {
	BaseTool
	config *config.Config
}

func NewSublist3r(cfg *config.Config) *Sublist3r {
	return &Sublist3r{
		BaseTool: BaseTool{
			ToolName:  "sublist3r",
			ToolDesc:  "Fast subdomains enumeration tool",
			ToolPhase: 1,
			Command:   "sublist3r",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (s *Sublist3r) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "sublist3r.txt")

	args := []string{
		"-d", domain,
		"-o", outputFile,
	}

	output, err := RunCommand(ctx, "sublist3r", args...)
	if err != nil {
		return "", fmt.Errorf("sublist3r failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
