package port

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/pkg/output/terminal"
)

// Scanner handles port scanning operations
type Scanner struct {
	InputFile string
	OutputDir string
}

// ScanResult contains port scanning results
type ScanResult struct {
	TotalHosts    int
	OpenPorts     int
	Services      []ServiceInfo
	Hosts         []HostInfo
	Duration      time.Duration
	FailedHosts   int
}

// HostInfo represents a scanned host with OS detection
type HostInfo struct {
	IP       string
	OS       string
	Accuracy string
	Services []ServiceInfo
}

// ServiceInfo represents a discovered service
type ServiceInfo struct {
	IP          string
	Port        int
	Protocol    string
	State       string
	Service     string
	Version     string
	Product     string
	ExtraInfo   string
	CVEs        []string
}

// NewScanner creates a new port scanner
func NewScanner(inputFile, outputDir string) *Scanner {
	return &Scanner{
		InputFile: inputFile,
		OutputDir: outputDir,
	}
}

// Run executes Nmap port scanning
func (s *Scanner) Run(ctx context.Context) (*ScanResult, error) {
	outputFile := filepath.Join(s.OutputDir, "nmap_results.txt")
	xmlOutputFile := filepath.Join(s.OutputDir, "nmap_results.xml")

	// Check if Nmap is installed
	if err := checkToolExists("nmap"); err != nil {
		terminal.PrintToolSkipped("Nmap", "not installed")
		// Create empty files to avoid errors
		os.Create(outputFile)
		os.Create(xmlOutputFile)
		return &ScanResult{TotalHosts: 0}, nil
	}

	// Verify input file exists
	if _, err := os.Stat(s.InputFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("input file not found: %s", s.InputFile)
	}

	terminal.PrintToolStarting("Nmap")
	start := time.Now()

	// Build Nmap command
	args := s.buildNmapArgs(xmlOutputFile)

	cmd := exec.CommandContext(ctx, "nmap", args...)

	// Capture output for progress monitoring
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nmap: %v", err)
	}

	// Monitor progress
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			// Nmap outputs progress info to stdout
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			// Monitor errors if needed
		}
	}()

	// Wait for completion with animated dots
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	elapsed := time.Duration(0)
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinnerIdx := 0
	for {
		select {
		case <-ticker.C:
			elapsed += time.Second
			terminal.PrintToolRunning("Nmap", spinners[spinnerIdx], elapsed, "")
			spinnerIdx = (spinnerIdx + 1) % len(spinners)
		case err := <-done:
			if err != nil {
				terminal.PrintToolFailed("Nmap", err, time.Since(start))
				os.Create(outputFile)
				os.Create(xmlOutputFile)
				return &ScanResult{TotalHosts: 0}, nil
			}
			goto finished
		case <-ctx.Done():
			cmd.Process.Kill()
			return nil, ctx.Err()
		}
	}

finished:
	// Parse results
	result := &ScanResult{
		Duration: time.Since(start),
	}

	// Parse XML output for detailed results
	services, hosts, err := parseNmapXML(xmlOutputFile)
	if err == nil {
		result.Services = services
		result.Hosts = hosts
		result.OpenPorts = len(services)
		result.TotalHosts = len(hosts)
	}

	// Convert XML to human-readable text
	if err := s.convertToText(xmlOutputFile, outputFile); err != nil {
		// If conversion fails, at least create empty file
		os.Create(outputFile)
	}

	terminal.PrintToolCompleted("Nmap", result.OpenPorts, result.Duration)

	return result, nil
}

// buildNmapArgs constructs Nmap command arguments
func (s *Scanner) buildNmapArgs(xmlOutput string) []string {
	// Single mode: Top 10 most critical ports only
	// 21=FTP, 22=SSH, 23=Telnet, 25=SMTP, 80=HTTP, 443=HTTPS,
	// 3306=MySQL, 3389=RDP, 5432=PostgreSQL, 8080=HTTP-Alt
	args := []string{
		"-iL", s.InputFile, // Input from file
		"-oX", xmlOutput,   // XML output
		"-p", "21,22,23,25,80,443,3306,3389,5432,8080",
		"-T4",               // Aggressive timing
		"-sV",               // Service version detection
		"--version-intensity", "9", // Maximum version detection intensity (0-9, more accurate)
		"--version-all",     // Try all probes for version detection (more accurate)
		"-sC",               // Script scanning (default NSE scripts)
		"-O",                // OS detection
		"--osscan-guess",    // Aggressive OS guessing
		"-Pn",               // Skip host discovery
		"--open",            // Only show open ports
		"--reason",          // Show reason for port state
		"-v",                // Verbose output
		"--stats-every", "30s", // Progress updates
	}

	return args
}

// convertToText converts XML output to human-readable format
func (s *Scanner) convertToText(xmlFile, textFile string) error {
	// Read XML and write simple text format
	content, err := os.ReadFile(xmlFile)
	if err != nil {
		return err
	}

	// For now, just copy the content
	// In a real implementation, you'd parse XML and format nicely
	return os.WriteFile(textFile, content, 0644)
}

// countUniqueHosts counts unique IP addresses in services
func countUniqueHosts(services []ServiceInfo) int {
	seen := make(map[string]bool)
	for _, svc := range services {
		seen[svc.IP] = true
	}
	return len(seen)
}

// checkToolExists verifies if a tool is installed
func checkToolExists(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("%s not found in PATH", toolName)
	}
	return nil
}
