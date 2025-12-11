package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the configuration structure
type Config struct {
	APIKeys  APIKeys  `yaml:"api_keys"`
	Paths    Paths    `yaml:"paths"`
	Settings Settings `yaml:"scan"`
}

// APIKeys holds all API keys
type APIKeys struct {
	Chaos  string `yaml:"chaos"`
	Shodan string `yaml:"shodan"`
}

// Paths holds custom paths
type Paths struct {
	Resolvers string `yaml:"resolvers"`
	Wordlist  string `yaml:"wordlist"`
}

// Settings holds scan settings
type Settings struct {
	DefaultThreads   int `yaml:"default_threads"`
	DefaultRateLimit int `yaml:"default_rate_limit"`
	DefaultTimeout   int `yaml:"default_timeout"`
}

// LoadConfig loads configuration from config.yaml
func LoadConfig() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Initialize default configs if not exists
		if err := InitializeDefaultConfigs(); err != nil {
			return nil, fmt.Errorf("failed to initialize config: %v", err)
		}
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return &config, nil
}
