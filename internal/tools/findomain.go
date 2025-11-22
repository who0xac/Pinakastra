package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Findomain struct {
	BaseTool
	config *config.Config
}

func NewFindomain(cfg *config.Config) *Findomain {
	return &Findomain{
		BaseTool: BaseTool{
			ToolName:  "findomain",
			ToolDesc:  "Fast subdomain enumeration tool",
			ToolPhase: 1,
			Command:   "findomain",
			Timeout:   5 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (f *Findomain) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), f.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "findomain.txt")

	args := []string{
		"-t", domain,
		"-u", outputFile,
		"-q",
	}

	output, err := RunCommand(ctx, "findomain", args...)
	if err != nil {
		return "", fmt.Errorf("findomain failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
