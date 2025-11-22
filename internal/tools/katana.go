package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Katana struct {
	BaseTool
	config *config.Config
}

func NewKatana(cfg *config.Config) *Katana {
	return &Katana{
		BaseTool: BaseTool{
			ToolName:  "katana",
			ToolDesc:  "Next-generation crawling framework",
			ToolPhase: 5,
			Command:   "katana",
			Timeout:   15 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (k *Katana) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.Timeout)
	defer cancel()

	httpxFile := filepath.Join(outputDir, "httpx.txt")
	outputFile := filepath.Join(outputDir, "katana.txt")

	var args []string
	if _, err := os.Stat(httpxFile); err == nil {
		args = []string{
			"-list", httpxFile,
			"-o", outputFile,
			"-silent",
		}
	} else {
		args = []string{
			"-u", "https://" + domain,
			"-o", outputFile,
			"-silent",
		}
	}

	output, err := RunCommand(ctx, "katana", args...)
	if err != nil {
		return "", fmt.Errorf("katana failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
