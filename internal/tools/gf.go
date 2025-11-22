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
			ToolPhase: 6,
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

	// gf reads from stdin, so we'll use cat to pipe the content
	// Command: cat gau.txt | gf xss
	catCmd := fmt.Sprintf("cat %s | gf xss", gauFile)

	output, err := RunCommand(ctx, "sh", "-c", catCmd)
	if err != nil {
		// gf might return error if no patterns found, but that's ok
		// Just return empty output
		if err := os.WriteFile(outputFile, []byte(""), 0644); err != nil {
			return "", nil
		}
		return "", nil
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
