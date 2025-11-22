package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Nuclei struct {
	BaseTool
	config *config.Config
}

func NewNuclei(cfg *config.Config) *Nuclei {
	return &Nuclei{
		BaseTool: BaseTool{
			ToolName:  "nuclei",
			ToolDesc:  "Vulnerability scanner based on templates",
			ToolPhase: 8,
			Command:   "nuclei",
			Timeout:   30 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (n *Nuclei) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), n.Timeout)
	defer cancel()

	httpxFile := filepath.Join(outputDir, "httpx.txt")
	outputFile := filepath.Join(outputDir, "nuclei.txt")

	if _, err := os.Stat(httpxFile); os.IsNotExist(err) {
		return "", fmt.Errorf("no httpx file found")
	}

	args := []string{
		"-l", httpxFile,
		"-o", outputFile,
		"-silent",
		"-severity", "critical,high,medium",
	}

	output, err := RunCommand(ctx, "nuclei", args...)
	if err != nil {
		return "", fmt.Errorf("nuclei failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
