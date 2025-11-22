package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Subjs struct {
	BaseTool
	config *config.Config
}

func NewSubjs(cfg *config.Config) *Subjs {
	return &Subjs{
		BaseTool: BaseTool{
			ToolName:  "subjs",
			ToolDesc:  "Fetches javascript files from URLs",
			ToolPhase: 7,
			Command:   "subjs",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (s *Subjs) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	httpxFile := filepath.Join(outputDir, "httpx.txt")
	outputFile := filepath.Join(outputDir, "subjs.txt")

	var args []string
	if _, err := os.Stat(httpxFile); err == nil {
		args = []string{
			"-i", httpxFile,
		}
	} else {
		args = []string{
			"-i", domain,
		}
	}

	output, err := RunCommand(ctx, "subjs", args...)
	if err != nil {
		return "", fmt.Errorf("subjs failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
