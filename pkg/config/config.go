package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// GetConfigDir returns the configuration directory path (Linux only)
func GetConfigDir() (string, error) {
	// Linux: ~/.config/pinakastra
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}

	configDir := filepath.Join(home, ".config", "pinakastra")
	return configDir, nil
}

// EnsureConfigDir creates the config directory structure if it doesn't exist
func EnsureConfigDir() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}

	// Create main config directory
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	// Create subdirectories
	dirs := []string{
		filepath.Join(configDir, "wordlists"),
		filepath.Join(configDir, "configs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	return configDir, nil
}

// InitializeDefaultConfigs creates default configuration files
func InitializeDefaultConfigs() error {
	configDir, err := EnsureConfigDir()
	if err != nil {
		return err
	}

	// Create resolvers.txt if it doesn't exist
	resolversPath := filepath.Join(configDir, "configs", "resolvers.txt")
	if _, err := os.Stat(resolversPath); os.IsNotExist(err) {
		defaultResolvers := `1.1.1.1
8.8.8.8
8.8.4.4
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
`
		if err := os.WriteFile(resolversPath, []byte(defaultResolvers), 0644); err != nil {
			return fmt.Errorf("failed to create resolvers.txt: %v", err)
		}
	}

	// Create subdomains wordlist if it doesn't exist
	subdomainsPath := filepath.Join(configDir, "wordlists", "subdomains.txt")
	if _, err := os.Stat(subdomainsPath); os.IsNotExist(err) {
		defaultSubdomains := `www
api
mail
ftp
admin
dev
staging
test
beta
cdn
portal
secure
vpn
remote
app
mobile
shop
store
blog
forum
help
support
docs
static
assets
img
images
media
upload
downloads
`
		if err := os.WriteFile(subdomainsPath, []byte(defaultSubdomains), 0644); err != nil {
			return fmt.Errorf("failed to create subdomains.txt: %v", err)
		}
	}

	// Create config.yaml if it doesn't exist
	configPath := filepath.Join(configDir, "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig := `api_keys:
  chaos: ""
  shodan: ""

paths:
  resolvers: ""
  wordlist: ""

scan:
  default_threads: 1000
  default_rate_limit: 100
  default_timeout: 5
`
		if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
			return fmt.Errorf("failed to create config.yaml: %v", err)
		}
	}

	return nil
}

// GetResolversPath returns the path to resolvers.txt
func GetResolversPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "configs", "resolvers.txt"), nil
}

// GetWordlistPath returns the path to subdomains wordlist
func GetWordlistPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "wordlists", "subdomains.txt"), nil
}

// GetConfigPath returns the path to config.yaml
func GetConfigPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.yaml"), nil
}
