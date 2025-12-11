package formatter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TXTFormatter handles plain text output
type TXTFormatter struct {
	OutputPath string
}

// NewTXTFormatter creates a new TXT formatter
func NewTXTFormatter(outputPath string) *TXTFormatter {
	return &TXTFormatter{
		OutputPath: outputPath,
	}
}

// Format writes scan results to TXT file
func (t *TXTFormatter) Format(result *ScanResult) error {
	outputFile := filepath.Join(t.OutputPath, "scan_results.txt")

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "%s\n", strings.Repeat("=", 80))
	fmt.Fprintf(file, "PINAKASTRA SCAN REPORT\n")
	fmt.Fprintf(file, "%s\n\n", strings.Repeat("=", 80))

	// Metadata
	fmt.Fprintf(file, "SCAN METADATA\n")
	fmt.Fprintf(file, "%s\n", strings.Repeat("-", 80))
	fmt.Fprintf(file, "Domain:       %s\n", result.Metadata.Domain)
	fmt.Fprintf(file, "Scan ID:      %s\n", result.Metadata.ScanID)
	fmt.Fprintf(file, "Start Time:   %s\n", result.Metadata.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "End Time:     %s\n", result.Metadata.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Duration:     %s\n", result.Metadata.Duration)
	fmt.Fprintf(file, "Mode:         %s\n", result.Metadata.Mode)
	fmt.Fprintf(file, "AI Enabled:   %v\n", result.Metadata.EnableAI)
	fmt.Fprintf(file, "TOR Enabled:  %v\n\n", result.Metadata.UseTor)

	// Subdomain results
	fmt.Fprintf(file, "SUBDOMAIN ENUMERATION\n")
	fmt.Fprintf(file, "%s\n", strings.Repeat("-", 80))
	fmt.Fprintf(file, "Total Found:     %d\n", result.Subdomains.TotalFound)
	fmt.Fprintf(file, "Duplicates:      %d\n", result.Subdomains.Duplicates)
	fmt.Fprintf(file, "Unique Count:    %d\n", result.Subdomains.UniqueCount)
	fmt.Fprintf(file, "API Endpoints:   %d\n", result.Subdomains.APICount)
	fmt.Fprintf(file, "Duration:        %s\n\n", result.Subdomains.Duration)

	fmt.Fprintf(file, "Tool Results:\n")
	for tool, count := range result.Subdomains.ToolResults {
		fmt.Fprintf(file, "  - %-15s : %d subdomains\n", tool, count)
	}
	fmt.Fprintf(file, "\n")

	fmt.Fprintf(file, "Subdomains:\n")
	for _, subdomain := range result.Subdomains.Subdomains {
		fmt.Fprintf(file, "  - %s\n", subdomain)
	}
	fmt.Fprintf(file, "\n")

	if len(result.Subdomains.APIs) > 0 {
		fmt.Fprintf(file, "API Endpoints:\n")
		for _, api := range result.Subdomains.APIs {
			fmt.Fprintf(file, "  - %s\n", api)
		}
		fmt.Fprintf(file, "\n")
	}

	// HTTP Probe results
	fmt.Fprintf(file, "HTTP PROBING\n")
	fmt.Fprintf(file, "%s\n", strings.Repeat("-", 80))
	fmt.Fprintf(file, "Total Probed:    %d\n", result.HTTPProbe.TotalProbed)
	fmt.Fprintf(file, "Live URLs:       %d\n", result.HTTPProbe.LiveCount)
	fmt.Fprintf(file, "Duration:        %s\n\n", result.HTTPProbe.Duration)

	fmt.Fprintf(file, "Live URLs:\n")
	for _, url := range result.HTTPProbe.LiveURLs {
		fmt.Fprintf(file, "  - %s", url.URL)
		if url.StatusCode > 0 {
			fmt.Fprintf(file, " [%d]", url.StatusCode)
		}
		fmt.Fprintf(file, "\n")
	}
	fmt.Fprintf(file, "\n")

	// Terminal output
	fmt.Fprintf(file, "TERMINAL OUTPUT\n")
	fmt.Fprintf(file, "%s\n", strings.Repeat("-", 80))
	for _, line := range result.TerminalOutput {
		fmt.Fprintf(file, "%s\n", line)
	}

	return nil
}
