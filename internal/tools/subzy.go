package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Subzy struct {
	BaseTool
	config *config.Config
}

func NewSubzy(cfg *config.Config) *Subzy {
	return &Subzy{
		BaseTool: BaseTool{
			ToolName:  "subzy",
			ToolDesc:  "Subdomain takeover vulnerability checker",
			ToolPhase: 6,
			Command:   "subzy",
			Timeout:   10 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (s *Subzy) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	subdomainFile := filepath.Join(outputDir, "subfinder.txt")
	outputFile := filepath.Join(outputDir, "subzy.txt")

	if _, err := os.Stat(subdomainFile); os.IsNotExist(err) {
		return "", fmt.Errorf("no subdomain file found")
	}

	args := []string{
		"run",
		"--targets", subdomainFile,
		"--hide_fails",
	}

	output, err := RunCommand(ctx, "subzy", args...)
	if err != nil {
		return "", fmt.Errorf("subzy failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
