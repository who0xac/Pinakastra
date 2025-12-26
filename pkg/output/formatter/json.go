package formatter

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// JSONFormatter handles JSON output
type JSONFormatter struct {
	OutputPath string
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(outputPath string) *JSONFormatter {
	return &JSONFormatter{
		OutputPath: outputPath,
	}
}

// Format writes scan results to JSON file
func (j *JSONFormatter) Format(result *ScanResult) error {
	// Create output file
	outputFile := filepath.Join(j.OutputPath, "scan_results.json")

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Marshal with indentation for readability
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		return err
	}

	return nil
}
