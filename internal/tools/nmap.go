package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Nmap struct {
	BaseTool
	config *config.Config
}

func NewNmap(cfg *config.Config) *Nmap {
	return &Nmap{
		BaseTool: BaseTool{
			ToolName:  "nmap",
			ToolDesc:  "Network port scanner",
			ToolPhase: 3,
			Command:   "nmap",
			Timeout:   20 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (nm *Nmap) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nm.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "nmap.txt")

	args := []string{
		"-sV",
		"-T4",
		"-oN", outputFile,
		domain,
	}

	output, err := RunCommand(ctx, "nmap", args...)
	if err != nil {
		return "", fmt.Errorf("nmap failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
