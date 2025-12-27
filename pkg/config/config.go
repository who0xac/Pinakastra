package config

import (
	"fmt"
	"io"
	"net/http"
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
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
94.140.14.14
94.140.15.15
76.76.2.0
76.76.10.0
185.228.168.9
185.228.169.9
64.6.64.6
64.6.65.6
77.88.8.8
77.88.8.1
84.200.69.80
84.200.70.40
156.154.70.1
156.154.71.1
216.146.35.35
216.146.36.36
`
		if err := os.WriteFile(resolversPath, []byte(defaultResolvers), 0644); err != nil {
			return fmt.Errorf("failed to create resolvers.txt: %v", err)
		}
	}

	// Download subdomains wordlist if it doesn't exist
	subdomainsPath := filepath.Join(configDir, "wordlists", "subdomains.txt")
	if _, err := os.Stat(subdomainsPath); os.IsNotExist(err) {
		// Try to download from SecLists
		wordlistURL := "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
		fmt.Printf("📥 Downloading subdomain wordlist (20K entries)...\n")
		if err := downloadFile(subdomainsPath, wordlistURL); err != nil {
			fmt.Printf("⚠️  Download failed: %v\n", err)
			fmt.Printf("📝 Creating fallback wordlist...\n")
			// If download fails, create a small default wordlist
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
		} else {
			fmt.Printf("✅ Wordlist downloaded successfully (20,000 subdomains)\n")
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

// downloadFile downloads a file from a URL and saves it to the specified path
func downloadFile(filepath string, url string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}
