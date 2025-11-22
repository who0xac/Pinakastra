package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Crtsh struct {
	BaseTool
	config *config.Config
}

func NewCrtsh(cfg *config.Config) *Crtsh {
	return &Crtsh{
		BaseTool: BaseTool{
			ToolName:  "crtsh",
			ToolDesc:  "Certificate transparency logs",
			ToolPhase: 1,
			Command:   "crtsh",
			Timeout:   5 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (c *Crtsh) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "crtsh.txt")

	args := []string{
		domain,
	}

	output, err := RunCommand(ctx, "crtsh", args...)
	if err != nil {
		return "", fmt.Errorf("crtsh failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
