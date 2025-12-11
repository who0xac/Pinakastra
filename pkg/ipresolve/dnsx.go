package ipresolve

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

// IPResolver handles IP resolution with dnsx
type IPResolver struct {
	InputFile string
	OutputDir string
	Threads   int
}

// ResolveResult contains IP resolution results
type ResolveResult struct {
	ResolvedIPs   map[string][]string // hostname -> IPs
	TotalResolved int
	Duration      time.Duration
	Error         error
}

// NewIPResolver creates a new IP resolver instance
func NewIPResolver(inputFile, outputDir string) *IPResolver {
	return &IPResolver{
		InputFile: inputFile,
		OutputDir: outputDir,
		Threads:   100,
	}
}

// Run executes IP resolution
func (r *IPResolver) Run(ctx context.Context) (*ResolveResult, error) {
	start := time.Now()
	result := &ResolveResult{
		ResolvedIPs: make(map[string][]string),
	}

	terminal.PrintSectionHeader("IP RESOLUTION")

	// Check if dnsx is installed
	if err := checkToolExists("dnsx"); err != nil {
		return nil, fmt.Errorf("dnsx not installed: %v", err)
	}

	// Verify input file exists
	if !fileExists(r.InputFile) {
		return nil, fmt.Errorf("input file not found: %s", r.InputFile)
	}

	// Extract hostnames from live URLs
	hostnamesFile := filepath.Join(r.OutputDir, "live_hostnames.txt")
	if err := r.extractHostnames(r.InputFile, hostnamesFile); err != nil {
		return nil, fmt.Errorf("failed to extract hostnames: %v", err)
	}

	// Count hostnames
	totalHosts, err := countFileLines(hostnamesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to count hostnames: %v", err)
	}

	terminal.PrintToolStarting("DNSX", fmt.Sprintf("resolving IPs for %d hosts", totalHosts))
	fmt.Println()

	// Prepare output file
	resolvedIPsFile := filepath.Join(r.OutputDir, "resolved_ips.txt")

	// Build dnsx command
	args := []string{
		"-l", hostnamesFile,
		"-a",                               // A records
		"-resp",                            // Show responses
		"-o", resolvedIPsFile,              // Output file
		"-t", fmt.Sprintf("%d", r.Threads), // Threads
		"-silent",                          // Silent mode
	}

	cmd := exec.CommandContext(ctx, "dnsx", args...)

	// Run command
	output, err := cmd.CombinedOutput()
	if err != nil {
		// dnsx might fail on some hosts but still produce results
		if !fileExists(resolvedIPsFile) {
			return nil, fmt.Errorf("dnsx failed: %v - %s", err, string(output))
		}
	}

	// Parse resolved IPs
	if err := r.parseResolvedIPs(resolvedIPsFile, result); err != nil {
		return nil, fmt.Errorf("failed to parse results: %v", err)
	}

	// Extract and save just IP addresses
	ipsOnlyFile := filepath.Join(r.OutputDir, "ips_only.txt")
	if err := r.extractIPsOnly(resolvedIPsFile, ipsOnlyFile); err != nil {
		return nil, fmt.Errorf("failed to extract IPs: %v", err)
	}

	result.Duration = time.Since(start)
	terminal.PrintToolCompleted("DNSX", result.TotalResolved, result.Duration)

	// Print summary
	terminal.PrintIPResolutionSummary(totalHosts, result.TotalResolved)

	return result, nil
}

// extractHostnames extracts hostnames from URLs (removes protocol and path)
func (r *IPResolver) extractHostnames(inputFile, outputFile string) error {
	input, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer output.Close()

	// Regex to extract hostname from URL
	urlPattern := regexp.MustCompile(`^https?://([^/]+)`)

	scanner := bufio.NewScanner(input)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Extract hostname
		var hostname string
		if matches := urlPattern.FindStringSubmatch(line); len(matches) > 1 {
			hostname = matches[1]
		} else {
			// If no protocol, assume it's already a hostname
			hostname = line
		}

		// Remove port if present
		if idx := strings.Index(hostname, ":"); idx != -1 {
			hostname = hostname[:idx]
		}

		// Deduplicate
		if !seen[hostname] {
			fmt.Fprintln(output, hostname)
			seen[hostname] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// parseResolvedIPs parses dnsx output
func (r *IPResolver) parseResolvedIPs(resolvedFile string, result *ResolveResult) error {
	file, err := os.Open(resolvedFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// dnsx output format: hostname [ip1,ip2,...]
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			hostname := parts[0]
			ipsStr := strings.Trim(parts[1], "[]")
			ips := strings.Split(ipsStr, ",")

			result.ResolvedIPs[hostname] = ips
			result.TotalResolved++
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// extractIPsOnly extracts just IP addresses from dnsx output
func (r *IPResolver) extractIPsOnly(resolvedFile, outputFile string) error {
	file, err := os.Open(resolvedFile)
	if err != nil {
		return err
	}
	defer file.Close()

	output, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer output.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// dnsx output format: hostname [ip1,ip2,...]
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			ipsStr := strings.Trim(parts[1], "[]")
			ips := strings.Split(ipsStr, ",")

			// Write each IP on its own line (deduplicated)
			for _, ip := range ips {
				ip = strings.TrimSpace(ip)
				if ip != "" && !seen[ip] {
					fmt.Fprintln(output, ip)
					seen[ip] = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// checkToolExists verifies if a tool is installed
func checkToolExists(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("%s not found in PATH", toolName)
	}
	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// countFileLines counts non-empty lines in a file
func countFileLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return count, nil
}
