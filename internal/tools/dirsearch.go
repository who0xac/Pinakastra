package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Dirsearch struct {
	BaseTool
	config *config.Config
}

func NewDirsearch(cfg *config.Config) *Dirsearch {
	return &Dirsearch{
		BaseTool: BaseTool{
			ToolName:  "dirsearch",
			ToolDesc:  "Web path scanner",
			ToolPhase: 7,
			Command:   "dirsearch",
			Timeout:   15 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (d *Dirsearch) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "dirsearch.txt")

	args := []string{
		"-u", "https://" + domain,
		"-o", outputFile,
		"-q",
	}

	output, err := RunCommand(ctx, "dirsearch", args...)
	if err != nil {
		return "", fmt.Errorf("dirsearch failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
