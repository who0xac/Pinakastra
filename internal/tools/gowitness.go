package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Gowitness struct {
	BaseTool
	config *config.Config
}

func NewGowitness(cfg *config.Config) *Gowitness {
	return &Gowitness{
		BaseTool: BaseTool{
			ToolName:  "gowitness",
			ToolDesc:  "Web screenshot utility",
			ToolPhase: 4,
			Command:   "gowitness",
			Timeout:   20 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (g *Gowitness) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), g.Timeout)
	defer cancel()

	httpxFile := filepath.Join(outputDir, "httpx.txt")
	screenshotDir := filepath.Join(outputDir, "screenshots")

	if _, err := os.Stat(httpxFile); os.IsNotExist(err) {
		return "", fmt.Errorf("no httpx file found")
	}

	os.MkdirAll(screenshotDir, 0755)

	args := []string{
		"file",
		"-f", httpxFile,
		"-P", screenshotDir,
	}

	output, err := RunCommand(ctx, "gowitness", args...)
	if err != nil {
		return "", fmt.Errorf("gowitness failed: %w", err)
	}

	return output, nil
}
