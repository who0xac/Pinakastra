package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Ffuf struct {
	BaseTool
	config *config.Config
}

func NewFfuf(cfg *config.Config) *Ffuf {
	return &Ffuf{
		BaseTool: BaseTool{
			ToolName:  "ffuf",
			ToolDesc:  "Fast web fuzzer",
			ToolPhase: 5,
			Command:   "ffuf",
			Timeout:   15 * time.Minute,
			OutputExt: ".txt",
		},
		config: cfg,
	}
}

func (f *Ffuf) Run(domain, outputDir string, cfg *config.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), f.Timeout)
	defer cancel()

	outputFile := filepath.Join(outputDir, "ffuf.txt")
	wordlist := cfg.GetDirectoriesWordlist()

	if wordlist == "" || !fileExists(wordlist) {
		return "", fmt.Errorf("wordlist not found")
	}

	args := []string{
		"-u", "https://" + domain + "/FUZZ",
		"-w", wordlist,
		"-o", outputFile,
		"-of", "csv",
		"-mc", "200,301,302,403",
		"-ac",
		"-s",
	}

	output, err := RunCommand(ctx, "ffuf", args...)
	if err != nil {
		return "", fmt.Errorf("ffuf failed: %w", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return output, nil
	}

	return string(data), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
