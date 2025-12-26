package subdomain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

// PassiveEnumerator coordinates all passive subdomain enumeration tools
type PassiveEnumerator struct {
	Domain       string
	OutputDir    string
	Resolvers    string
	ChaosAPIKey  string
	ShodanAPIKey string
	Wordlist     string
	SkipPuredns  bool
	Results      chan ToolResult
	errors       []error
	mu           sync.Mutex
}

// ToolResult represents the result from a single tool
type ToolResult struct {
	ToolName   string
	Subdomains []string
	Duration   time.Duration
	Error      error
}

// NewPassiveEnumerator creates a new passive enumerator
func NewPassiveEnumerator(domain, outputDir string) *PassiveEnumerator {
	return &PassiveEnumerator{
		Domain:      domain,
		OutputDir:   outputDir,
		Results:     make(chan ToolResult, 9),
		errors:      make([]error, 0),
	}
}

// Run executes all subdomain enumeration tools sequentially (one by one)
func (p *PassiveEnumerator) Run(ctx context.Context) ([]string, error) {
	// Print section header
	terminal.PrintSectionHeader("SUBDOMAIN ENUMERATION")

	// Create output directory
	if err := os.MkdirAll(p.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Define tools to run sequentially (Puredns will run last)
	tools := []func(context.Context) ToolResult{
		p.runSubfinder,
		p.runFindomain,
		p.runAssetfinder,
		p.runSublist3r,
		p.runChaos,
		p.runCrtsh,
		p.runShodan,
	}

	// Collect results
	allSubdomains := make([]string, 0)
	successCount := 0

	// Run each tool sequentially
	for _, toolFunc := range tools {
		result := toolFunc(ctx)
		if result.Error != nil {
			terminal.PrintToolFailed(result.ToolName, result.Error, result.Duration)
			p.addError(result.Error)
		} else {
			successCount++
			terminal.PrintToolCompleted(result.ToolName, len(result.Subdomains), result.Duration)
			allSubdomains = append(allSubdomains, result.Subdomains...)
		}
	}

	// Run Puredns last (unless explicitly skipped)
	if !p.SkipPuredns {
		result := p.runPuredns(ctx)
		if result.Error != nil {
			terminal.PrintToolFailed(result.ToolName, result.Error, result.Duration)
			p.addError(result.Error)
		} else {
			successCount++
			terminal.PrintToolCompleted(result.ToolName, len(result.Subdomains), result.Duration)
			allSubdomains = append(allSubdomains, result.Subdomains...)
		}
	}

	// Calculate statistics
	totalFound := len(allSubdomains)

	// Clean and merge all subdomain files
	terminal.PrintProgress("Merging and cleaning subdomains...")
	cleanedSubdomains, err := cleanAndMergeSubdomains(p.OutputDir, p.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to clean and merge subdomains: %v", err)
	}

	// Validate cleaned subdomains
	terminal.PrintProgress("Validating subdomains...")
	validated := validateSubdomains(cleanedSubdomains, p.Domain)

	// Calculate duplicates
	duplicates := totalFound - len(validated)

	// Print summary
	terminal.PrintSubdomainSummary(totalFound, duplicates, len(validated))

	// Save final results
	finalFile := filepath.Join(p.OutputDir, "subdomains.txt")
	if err := saveSubdomains(finalFile, validated); err != nil {
		return nil, fmt.Errorf("failed to save final results: %v", err)
	}
	terminal.PrintSuccess(fmt.Sprintf("Final subdomains saved to: %s", finalFile))

	return validated, nil
}

// addError safely adds an error to the error list
func (p *PassiveEnumerator) addError(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errors = append(p.errors, err)
}

// GetErrors returns all errors encountered
func (p *PassiveEnumerator) GetErrors() []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.errors
}

// runCommand executes a command and handles errors
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("command cancelled: %v", ctx.Err())
		}
		return output, fmt.Errorf("command failed: %v - %s", err, string(output))
	}

	return output, nil
}

// checkToolExists checks if a tool is installed
func checkToolExists(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("%s not found in PATH - please install it", toolName)
	}
	return nil
}
