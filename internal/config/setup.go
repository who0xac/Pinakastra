package config

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/fatih/color"
)

// Setup creates necessary directories and downloads required files on first run
func Setup() error {
	configDir := expandPath("~/.config/pinakastra")
	wordlistsDir := filepath.Join(configDir, "wordlists")

	// Check if already setup
	configFile := filepath.Join(configDir, "config.yaml")
	if fileExists(configFile) {
		return nil // Already setup
	}

	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)

	fmt.Println()
	yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	yellow.Println("           🔧 FIRST TIME SETUP - PINAKASTRA")
	yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Create directories
	cyan.Print("  [1/4] Creating directories...")
	if err := os.MkdirAll(wordlistsDir, 0755); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}
	green.Println(" ✓")

	// Create default config file
	cyan.Print("  [2/4] Creating config file...")
	if err := createDefaultConfig(configFile); err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}
	green.Println(" ✓")

	// Download resolvers
	cyan.Print("  [3/4] Downloading DNS resolvers...")
	resolversFile := filepath.Join(configDir, "resolvers.txt")
	if err := downloadFile(
		"https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt",
		resolversFile,
	); err != nil {
		yellow.Printf(" ⚠ Failed (you can add manually)\n")
	} else {
		green.Println(" ✓")
	}

	// Download wordlists
	cyan.Print("  [4/4] Downloading wordlists (this may take a moment)...")

	subdomainsFile := filepath.Join(wordlistsDir, "subdomains.txt")
	if err := downloadFile(
		"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
		subdomainsFile,
	); err != nil {
		yellow.Printf(" ⚠ Subdomains wordlist failed\n")
	}

	directoriesFile := filepath.Join(wordlistsDir, "directories.txt")
	if err := downloadFile(
		"https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
		directoriesFile,
	); err != nil {
		yellow.Printf(" ⚠ Directories wordlist failed\n")
	} else {
		green.Println(" ✓")
	}

	fmt.Println()
	green.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	green.Println("            ✅ SETUP COMPLETE!")
	green.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	cyan.Printf("  📁 Config file: %s\n", configFile)
	fmt.Println()
	yellow.Println("  ⚡ NEXT STEPS:")
	fmt.Println("     1. Edit config file to add your API keys:")
	cyan.Printf("        nano %s\n", configFile)
	fmt.Println()
	fmt.Println("     2. Add your API keys (optional but recommended):")
	fmt.Println("        - shodan_api_key: https://account.shodan.io/")
	fmt.Println("        - chaos_api_key: https://chaos.projectdiscovery.io/")
	fmt.Println("        - github_token: https://github.com/settings/tokens")
	fmt.Println()
	fmt.Println("     3. Or use environment variables:")
	fmt.Println("        export SHODAN_API_KEY=\"your_key\"")
	fmt.Println("        export CHAOS_API_KEY=\"your_key\"")
	fmt.Println()
	yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	return nil
}

func createDefaultConfig(path string) error {
	configContent := `# Pinakastra Configuration
# Add your API keys below

# API Keys
api_keys:
  shodan_api_key: ""
  chaos_api_key: ""
  github_token: ""
  gitlab_token: ""
  telegram_bot_token: ""
  telegram_chat_id: ""

# Paths
paths:
  resolvers: "~/.config/pinakastra/resolvers.txt"
  subdomains_wordlist: "~/.config/pinakastra/wordlists/subdomains.txt"
  directories_wordlist: "~/.config/pinakastra/wordlists/directories.txt"
  amass_config: "~/.config/amass/config.yaml"
  jsa_path: "~/tools/JSA"

# Storage
storage:
  base_path: "~/recon-results"

# Notifications
notifications:
  telegram: false
  desktop: false
  telegram_bot_token: ""
  telegram_chat_id: ""
`
	return os.WriteFile(path, []byte(configContent), 0644)
}

func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
