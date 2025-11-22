package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Dnsx struct {
	BaseTool
	config *config.Config
}

func NewDnsx(cfg *config.Config) *Dnsx {
	return &Dnsx{
		BaseTool: BaseTool{
			ToolName:  "dnsx",
			ToolDesc:  "Fast DNS toolkit",
			ToolPhase: 2,
			Command:   "dnsx",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (d *Dnsx) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	subdomainFile := filepath.Join(outputDir, "subfinder.txt")
	outputFile := filepath.Join(outputDir, "dnsx.txt")

	if _, err := os.Stat(subdomainFile); os.IsNotExist(err) {
		return "", fmt.Errorf("no subdomain file found")
	}

	args := []string{
		"-l", subdomainFile,
		"-o", outputFile,
		"-silent",
		"-a",
		"-resp",
	}

	if cfg.Paths.Resolvers != "" {
		if _, err := os.Stat(cfg.Paths.Resolvers); err == nil {
			args = append(args, "-r", cfg.Paths.Resolvers)
		}
	}

	output, err := RunCommand(ctx, "dnsx", args...)
	if err != nil {
		return "", fmt.Errorf("dnsx failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
