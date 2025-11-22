package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Jq struct {
	BaseTool
	config *config.Config
}

func NewJq(cfg *config.Config) *Jq {
	return &Jq{
		BaseTool: BaseTool{
			ToolName:  "jq",
			ToolDesc:  "JSON processor",
			ToolPhase: 5,
			Command:   "jq",
			Timeout:   2 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (j *Jq) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), j.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "jq_processed.txt")

	// Just a placeholder - jq is typically used for processing JSON outputs from other tools
	args := []string{
		".",
	}

	output, err := RunCommand(ctx, "echo", "{\"message\": \"jq is available for JSON processing\"}")
	if err != nil {
		return "", fmt.Errorf("jq failed: %w", err)
	}

	if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
		return output, nil
	}

	return output, nil
}
