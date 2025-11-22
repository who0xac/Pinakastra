package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Puredns struct {
	BaseTool
	config *config.Config
}

func NewPuredns(cfg *config.Config) *Puredns {
	return &Puredns{
		BaseTool: BaseTool{
			ToolName:  "puredns",
			ToolDesc:  "Fast domain resolver and subdomain bruteforcing",
			ToolPhase: 2,
			Command:   "puredns",
			Timeout:   15 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (p *Puredns) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	subdomainFile := filepath.Join(outputDir, "subfinder.txt")
	outputFile := filepath.Join(outputDir, "puredns.txt")

	if _, err := os.Stat(subdomainFile); os.IsNotExist(err) {
		return "", fmt.Errorf("no subdomain file found")
	}

	args := []string{
		"resolve",
		subdomainFile,
		"-w", outputFile,
		"-q",
	}

	if cfg.Paths.Resolvers != "" {
		if _, err := os.Stat(cfg.Paths.Resolvers); err == nil {
			args = append(args, "-r", cfg.Paths.Resolvers)
		}
	}

	output, err := RunCommand(ctx, "puredns", args...)
	if err != nil {
		return "", fmt.Errorf("puredns failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
