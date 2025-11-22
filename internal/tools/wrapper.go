package tools

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Tool interface {
	Name() string
	Description() string
	Phase() int
	Run(domain, outputDir string, cfg *config.Config) (string, error)
	CountFindings(output string) int
	OutputFile(outputDir string) string
	IsInstalled() bool
	InstallCommand() string
}

type BaseTool struct {
	ToolName     string
	ToolDesc     string
	ToolPhase    int
	Command      string
	Args         []string
	Timeout      time.Duration
	OutputExt    string
}

func (t *BaseTool) Name() string {
	return t.ToolName
}

func (t *BaseTool) Description() string {
	return t.ToolDesc
}

func (t *BaseTool) Phase() int {
	return t.ToolPhase
}

func (t *BaseTool) IsInstalled() bool {
	_, err := exec.LookPath(t.Command)
	return err == nil
}

func (t *BaseTool) InstallCommand() string {
	return "go install github.com/" + t.Command + "@latest"
}

func (t *BaseTool) OutputFile(outputDir string) string {
	return outputDir + "/" + t.ToolName + t.OutputExt
}

func (t *BaseTool) CountFindings(output string) int {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return "", &CommandError{
				Command: name,
				Args:    args,
				Stderr:  stderr.String(),
				Err:     err,
			}
		}
		return "", err
	}

	return stdout.String(), nil
}

type CommandError struct {
	Command string
	Args    []string
	Stderr  string
	Err     error
}

func (e *CommandError) Error() string {
	return e.Command + ": " + e.Stderr
}
