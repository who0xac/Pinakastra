package ipresolve

import (
	"bufio"
	"context"
	"fmt"
	"net"
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
	ipsOnlyFile := filepath.Join(r.OutputDir, "ips_only.txt")

	// Build dnsx command: dnsx -l live_urls.txt -a -resp -silent
	args := []string{
		"-l", hostnamesFile,
		"-a",                               // A records
		"-resp",                            // Show responses
		"-silent",                          // Silent mode
		"-t", fmt.Sprintf("%d", r.Threads), // Threads
	}

	cmd := exec.CommandContext(ctx, "dnsx", args...)

	// Capture stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("dnsx failed to start: %v", err)
	}

	// Create files for saving output
	resolvedIPsFile := filepath.Join(r.OutputDir, "resolved_ips.txt")
	fullOutput, err := os.Create(resolvedIPsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create resolved_ips file: %v", err)
	}
	defer fullOutput.Close()

	// Extract IPs using regex and save both full output and IPs
	// Same pattern as: grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
	ipPattern := regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`)
	seen := make(map[string]bool)
	var allIPs []string

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		// Save full dnsx output line
		if line != "" {
			fmt.Fprintln(fullOutput, line)
		}

		// Extract all IPs from the line
		ips := ipPattern.FindAllString(line, -1)
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				allIPs = append(allIPs, ip)
			}
		}
	}

	// Wait for command to finish
	if err := cmd.Wait(); err != nil {
		// dnsx might fail on some hosts but still have found IPs
		if len(allIPs) == 0 {
			return nil, fmt.Errorf("dnsx failed: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading dnsx output: %v", err)
	}

	// Save unique IPs to separate file
	if len(allIPs) > 0 {
		ipsOutput, err := os.Create(ipsOnlyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create ips file: %v", err)
		}
		defer ipsOutput.Close()

		for _, ip := range allIPs {
			fmt.Fprintln(ipsOutput, ip)
		}
	}

	// Update result
	result.TotalResolved = len(allIPs)

	if len(allIPs) == 0 {
		terminal.PrintToolCompleted("DNSX", 0, time.Since(start))
		terminal.PrintIPResolutionSummary(totalHosts, 0)
		return result, nil
	}

	// Populate result with resolved IPs
	for _, ip := range allIPs {
		result.ResolvedIPs[ip] = []string{ip}
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

		// dnsx output format with -resp: hostname [A] [ip1] or hostname [A] [ip1,ip2]
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			hostname := parts[0]
			var ips []string

			// Extract IPs from all bracketed parts (skip [A], [AAAA], etc.)
			for _, part := range parts[1:] {
				if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
					content := strings.Trim(part, "[]")

					// Skip record types
					if content == "A" || content == "AAAA" || content == "CNAME" || content == "MX" || content == "NS" {
						continue
					}

					// Add IP if valid
					if net.ParseIP(content) != nil {
						ips = append(ips, content)
					}
				}
			}

			if len(ips) > 0 {
				result.ResolvedIPs[hostname] = ips
				result.TotalResolved++
			}
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

		// dnsx output format with -resp: hostname [A] [ip1] or hostname [A] [ip1,ip2]
		// Extract all IPs from brackets, skipping [A], [AAAA], [CNAME] etc.
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
				content := strings.Trim(part, "[]")

				// Skip record types (A, AAAA, CNAME, etc.)
				if content == "A" || content == "AAAA" || content == "CNAME" || content == "MX" || content == "NS" {
					continue
				}

				// Check if it looks like an IP address
				if net.ParseIP(content) != nil {
					if !seen[content] {
						fmt.Fprintln(output, content)
						seen[content] = true
					}
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
