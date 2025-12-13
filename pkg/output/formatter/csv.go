package formatter

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
)

// CSVFormatter handles CSV output
type CSVFormatter struct {
	OutputPath string
}

// NewCSVFormatter creates a new CSV formatter
func NewCSVFormatter(outputPath string) *CSVFormatter {
	return &CSVFormatter{
		OutputPath: outputPath,
	}
}

// Format writes scan results to CSV files
func (c *CSVFormatter) Format(result *ScanResult) error {
	// Create subdomains CSV
	if err := c.writeSubdomainsCSV(result); err != nil {
		return err
	}

	// Create API endpoints CSV
	if len(result.Subdomains.APIs) > 0 {
		if err := c.writeAPIsCSV(result); err != nil {
			return err
		}
	}

	// Create summary CSV
	if err := c.writeSummaryCSV(result); err != nil {
		return err
	}

	return nil
}

// writeSubdomainsCSV writes subdomains to CSV
func (c *CSVFormatter) writeSubdomainsCSV(result *ScanResult) error {
	outputFile := filepath.Join(c.OutputPath, "subdomains.csv")

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"Subdomain"})

	// Write subdomains
	for _, subdomain := range result.Subdomains.Subdomains {
		writer.Write([]string{subdomain})
	}

	return nil
}

// writeAPIsCSV writes API endpoints to CSV
func (c *CSVFormatter) writeAPIsCSV(result *ScanResult) error {
	outputFile := filepath.Join(c.OutputPath, "api_endpoints.csv")

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"API Endpoint"})

	// Write APIs
	for _, api := range result.Subdomains.APIs {
		writer.Write([]string{api})
	}

	return nil
}

// writeSummaryCSV writes scan summary to CSV
func (c *CSVFormatter) writeSummaryCSV(result *ScanResult) error {
	outputFile := filepath.Join(c.OutputPath, "scan_summary.csv")

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write metadata
	writer.Write([]string{"Metric", "Value"})
	writer.Write([]string{"Domain", result.Metadata.Domain})
	writer.Write([]string{"Scan ID", result.Metadata.ScanID})
	writer.Write([]string{"Start Time", result.Metadata.StartTime.Format("2006-01-02 15:04:05")})
	writer.Write([]string{"End Time", result.Metadata.EndTime.Format("2006-01-02 15:04:05")})
	writer.Write([]string{"Duration", result.Metadata.Duration})
	writer.Write([]string{"Mode", result.Metadata.Mode})
	writer.Write([]string{"AI Enabled", strconv.FormatBool(result.Metadata.EnableAI)})
	writer.Write([]string{"TOR Enabled", strconv.FormatBool(result.Metadata.UseTor)})
	writer.Write([]string{""})

	// Subdomain statistics
	writer.Write([]string{"Subdomain Statistics", ""})
	writer.Write([]string{"Total Found", strconv.Itoa(result.Subdomains.TotalFound)})
	writer.Write([]string{"Duplicates", strconv.Itoa(result.Subdomains.Duplicates)})
	writer.Write([]string{"Unique Count", strconv.Itoa(result.Subdomains.UniqueCount)})
	writer.Write([]string{"API Endpoints", strconv.Itoa(result.Subdomains.APICount)})
	writer.Write([]string{"Duration", result.Subdomains.Duration})
	writer.Write([]string{""})

	// HTTP Probe statistics
	writer.Write([]string{"HTTP Probe Statistics", ""})
	writer.Write([]string{"Total Probed", strconv.Itoa(result.HTTPProbe.TotalProbed)})
	writer.Write([]string{"Live URLs", strconv.Itoa(result.HTTPProbe.LiveCount)})
	writer.Write([]string{"Duration", result.HTTPProbe.Duration})
	writer.Write([]string{""})

	// Tool results
	writer.Write([]string{"Tool Results", ""})
	for tool, count := range result.Subdomains.ToolResults {
		writer.Write([]string{tool, strconv.Itoa(count)})
	}

	return nil
}
