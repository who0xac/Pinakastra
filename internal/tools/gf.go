package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Gf struct {
	BaseTool
	config *config.Config
}

func NewGf(cfg *config.Config) *Gf {
	return &Gf{
		BaseTool: BaseTool{
			ToolName:  "gf",
			ToolDesc:  "Wrapper around grep for patterns",
			ToolPhase: 5,
			Command:   "gf",
			Timeout:   5 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (g *Gf) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), g.Timeout)
	defer cancel()

	gauFile := filepath.Join(outputDir, "gau.txt")
	outputFile := filepath.Join(outputDir, "gf.txt")

	if _, err := os.Stat(gauFile); os.IsNotExist(err) {
		return "", fmt.Errorf("no gau file found")
	}

	data, err := os.ReadFile(gauFile)
	if err != nil {
		return "", fmt.Errorf("failed to read gau file: %w", err)
	}

	args := []string{
		"xss",
	}

	cmd := "echo"
	cmdArgs := []string{string(data)}
	
	output, err := RunCommand(ctx, cmd, cmdArgs...)
	if err != nil {
		return "", fmt.Errorf("gf failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
