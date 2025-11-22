package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/who0xac/pinakastra/internal/executor"
)

type Storage struct {
	basePath string
}

type ScanResult struct {
	Domain    string                          `json:"domain"`
	Timestamp time.Time                       `json:"timestamp"`
	Duration  string                          `json:"duration"`
	Results   map[string]*executor.ToolResult `json:"results"`
}

func New(basePath string) *Storage {
	return &Storage{
		basePath: basePath,
	}
}

func (s *Storage) GetDomainPath(domain string) string {
	return filepath.Join(s.basePath, domain)
}

func (s *Storage) EnsureDir(domain string) error {
	path := s.GetDomainPath(domain)
	return os.MkdirAll(path, 0755)
}

func (s *Storage) SaveResults(domain string, results map[string]*executor.ToolResult) error {
	if err := s.EnsureDir(domain); err != nil {
		return err
	}

	scanResult := ScanResult{
		Domain:    domain,
		Timestamp: time.Now(),
		Results:   results,
	}

	// Save as JSON
	jsonPath := filepath.Join(s.GetDomainPath(domain), "scan_results.json")
	if err := s.saveJSON(jsonPath, scanResult); err != nil {
		return err
	}

	return nil
}

func (s *Storage) saveJSON(path string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, jsonData, 0644)
}

func (s *Storage) LoadResults(domain string) (*ScanResult, error) {
	jsonPath := filepath.Join(s.GetDomainPath(domain), "scan_results.json")

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}

	var result ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *Storage) ListScans() ([]string, error) {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var domains []string
	for _, entry := range entries {
		if entry.IsDir() {
			domains = append(domains, entry.Name())
		}
	}

	return domains, nil
}

func (s *Storage) SaveToolOutput(domain, toolName, output string) error {
	if err := s.EnsureDir(domain); err != nil {
		return err
	}

	outputPath := filepath.Join(s.GetDomainPath(domain), toolName+".txt")
	return os.WriteFile(outputPath, []byte(output), 0644)
}

func (s *Storage) GetToolOutputPath(domain, toolName string) string {
	return filepath.Join(s.GetDomainPath(domain), toolName+".txt")
}
