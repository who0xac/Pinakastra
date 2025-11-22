package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Arjun struct {
	BaseTool
	config *config.Config
}

func NewArjun(cfg *config.Config) *Arjun {
	return &Arjun{
		BaseTool: BaseTool{
			ToolName:  "arjun",
			ToolDesc:  "HTTP parameter discovery suite",
			ToolPhase: 7,
			Command:   "arjun",
			Timeout:   15 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (a *Arjun) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "arjun.txt")

	args := []string{
		"-u", "https://" + domain,
		"-oT", outputFile,
		"-q",
	}

	output, err := RunCommand(ctx, "arjun", args...)
	if err != nil {
		return "", fmt.Errorf("arjun failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
