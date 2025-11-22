package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Massdns struct {
	BaseTool
	config *config.Config
}

func NewMassdns(cfg *config.Config) *Massdns {
	return &Massdns{
		BaseTool: BaseTool{
			ToolName:  "massdns",
			ToolDesc:  "High-performance DNS stub resolver",
			ToolPhase: 2,
			Command:   "massdns",
			Timeout:   15 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (m *Massdns) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.Timeout)
	defer cancel()

	subdomainFile := filepath.Join(outputDir, "subfinder.txt")
	outputFile := filepath.Join(outputDir, "massdns.txt")

	if _, err := os.Stat(subdomainFile); os.IsNotExist(err) {
		return "", fmt.Errorf("no subdomain file found")
	}

	resolvers := cfg.Paths.Resolvers
	if resolvers == "" || !fileExists(resolvers) {
		return "", fmt.Errorf("resolvers file not found")
	}

	args := []string{
		"-r", resolvers,
		"-t", "A",
		"-o", "S",
		"-w", outputFile,
		subdomainFile,
	}

	output, err := RunCommand(ctx, "massdns", args...)
	if err != nil {
		return "", fmt.Errorf("massdns failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}
