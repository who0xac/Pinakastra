package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/who0xac/pinakastra/pkg/checker"
	"github.com/who0xac/pinakastra/pkg/config"
	"github.com/who0xac/pinakastra/pkg/scanner"
)

const (
	version = "1.0.0"
	author  = "who0xac"
	banner  = `
____  _             _            _
|  _ \(_)_ __   __ _| | ____ _ __| |_ _ __ __ _
| |_) | | '_ \ / _' | |/ / _' / __| __| '__/ _' |
|  __/| | | | | (_| |   < (_| \__ \ |_| | | (_| |
|_|   |_|_| |_|\__,_|_|\_\__,_|___/\__|_|  \__,_|

🔱 Pinakastra 🔱
AI-Powered Penetration Testing Framework with Automated Reconnaissance

Version: %s
Author: %s

`
)

// printBanner prints the colorful banner
func printBanner() {
	// Dark, attractive colors - using regular (darker) versions
	cyan := color.New(color.FgCyan, color.Bold)      // Deep cyan for ASCII art
	magenta := color.New(color.FgMagenta, color.Bold) // Deep magenta for title
	blue := color.New(color.FgBlue, color.Bold)       // Deep blue for subtitle
	brightRed := color.New(color.FgHiRed, color.Bold) // Bright red for author (more visible)
	green := color.New(color.FgGreen)                 // Dark green for version

	cyan.Println(`
____  _             _            _
|  _ \(_)_ __   __ _| | ____ _ __| |_ _ __ __ _
| |_) | | '_ \ / _' | |/ / _' / __| __| '__/ _' |
|  __/| | | | | (_| |   < (_| \__ \ |_| | | (_| |
|_|   |_|_| |_|\__,_|_|\_\__,_|___/\__|_|  \__,_|`)

	magenta.Println("\n🔱 Pinakastra 🔱")
	blue.Println("AI-Powered Penetration Testing Framework with Automated Reconnaissance")

	fmt.Println()
	green.Printf("Version: %s\n", version)
	fmt.Print("Author: ")
	brightRed.Printf("%s\n\n", author)
}

var (
	// Global flags
	domain    string
	mode      string
	enableAI  bool
	output    string
	format    string
	outputDir string
	threads   int
	rateLimit int

	// Subdomain flags
	noBruteforce bool

	// Port scanning flags
	ports      string
	noPortscan bool

	// Proxy flags
	useTor bool
)

var rootCmd = &cobra.Command{
	Use:   "pinakastra",
	Short: "🔱 AI-Powered Attack Surface Discovery & Analysis",
	Long:  "", // Will be shown via custom help
	Run: func(cmd *cobra.Command, args []string) {
		// If no command specified, show help
		if domain == "" {
			printBanner()
			cmd.Help()
			return
		}
		// Default to scan command
		scanCmd.Run(cmd, args)
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target domain",
	Long:  "Perform comprehensive security assessment of target domain",
	Run: func(cmd *cobra.Command, args []string) {
		if domain == "" {
			fmt.Println("Error: Domain is required")
			fmt.Println("Usage: pinakastra -d target.com")
			os.Exit(1)
		}

		printBanner()
		fmt.Printf("Target: %s\n", domain)
		fmt.Printf("AI Analysis: %v\n", enableAI)
		fmt.Printf("TOR Proxy: %v\n", useTor)
		fmt.Println("\nInitializing Pinakastra...")
		fmt.Println()

		// Create scan configuration
		config := &scanner.ScanConfig{
			Domain:        domain,
			OutputDir:     outputDir,
			OutputFile:    output,
			OutputFormats: format,
			Mode:          mode,
			EnableAI:      enableAI,
			Threads:       threads,
			RateLimit:     rateLimit,
			UseTor:        useTor,
			NoBruteforce:  noBruteforce,
			NoPortscan:    noPortscan,
			Ports:         ports,
		}

		// Create scanner and run
		s := scanner.NewScanner(config)
		if err := s.Run(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var updateDBCmd = &cobra.Command{
	Use:   "update-db",
	Short: "Update CVE databases",
	Long:  "Download latest CISA KEV and Exploit-DB databases",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔄 Updating CVE databases...")
		fmt.Println("  → Downloading CISA KEV database...")
		fmt.Println("  → Downloading Exploit-DB database...")
		fmt.Println("TODO: Implement database update")
	},
}

var resumeCmd = &cobra.Command{
	Use:   "resume [scan-id]",
	Short: "Resume interrupted scan",
	Long:  "Resume a previously interrupted scan using its scan ID",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		scanID := args[0]
		fmt.Printf("🔄 Resuming scan: %s\n", scanID)
		fmt.Println("TODO: Implement resume functionality")
	},
}

var compareCmd = &cobra.Command{
	Use:   "compare [scan1.json] [scan2.json]",
	Short: "Compare two scan results",
	Long:  "Compare two scan results and highlight differences",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		scan1 := args[0]
		scan2 := args[1]
		fmt.Printf("🔍 Comparing scans:\n")
		fmt.Printf("  Scan 1: %s\n", scan1)
		fmt.Printf("  Scan 2: %s\n", scan2)
		fmt.Println("TODO: Implement compare functionality")
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		checkForUpdates()
	},
}

// checkForUpdates checks if a newer version is available on GitHub
func checkForUpdates() {
	blue := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()

	fmt.Println()
	fmt.Printf("%s %s\n", blue("→"), white("Checking for updates..."))

	// Fetch latest release from GitHub API
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/who0xac/Pinakastra/releases/latest", nil)
	if err != nil {
		fmt.Printf("%s %s\n", yellow("⚠"), yellow("Unable to check for updates"))
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s %s\n", yellow("⚠"), yellow("Unable to check for updates"))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// No releases found - this is expected for new repos
		fmt.Printf("%s %s\n", green("●"), green("Running latest development version"))
		fmt.Printf("   %s %s\n", blue("→"), white("No releases published yet"))
		return
	}

	if resp.StatusCode != 200 {
		fmt.Printf("%s %s\n", yellow("⚠"), yellow("Unable to check for updates"))
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		Name    string `json:"name"`
		HTMLURL string `json:"html_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		fmt.Printf("%s %s\n", yellow("⚠"), yellow("Unable to check for updates"))
		return
	}

	// Compare versions (remove 'v' prefix if present)
	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(version, "v")

	if latestVersion == currentVersion {
		fmt.Printf("%s %s\n", green("●"), green("You are running the latest version!"))
	} else if latestVersion > currentVersion {
		fmt.Printf("%s %s\n", yellow("●"), yellow(fmt.Sprintf("New version available: %s", bold(latestVersion))))
		fmt.Printf("   %s %s\n", blue("→"), white(fmt.Sprintf("Current version: %s", currentVersion)))
		fmt.Printf("   %s %s\n", blue("→"), white(fmt.Sprintf("Release: %s", release.HTMLURL)))
		fmt.Println()
		fmt.Printf("   %s\n", bold("Run 'pinakastra update' to upgrade"))
	} else {
		fmt.Printf("%s %s\n", green("●"), green("You are running the latest version!"))
	}
}

var checkCmd = &cobra.Command{
	Use:     "check",
	Aliases: []string{"c"},
	Short:   "Check if required tools are installed",
	Long:    "Verify that all required external tools are installed and accessible",
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		fmt.Println()
		checker.PrintToolStatus()
	},
}

var updateCmd = &cobra.Command{
	Use:     "update",
	Aliases: []string{"u"},
	Short:   "Update Pinakastra to the latest version",
	Long:    "Update Pinakastra binary to the latest version from GitHub",
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()

		blue := color.New(color.FgCyan).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()
		yellow := color.New(color.FgYellow).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()
		white := color.New(color.FgWhite).SprintFunc()
		bold := color.New(color.Bold).SprintFunc()

		fmt.Printf("%s %s\n", blue("→"), bold("Updating Pinakastra to the latest version..."))
		fmt.Println()

		// Show progress bar animation
		done := make(chan bool)
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			spinnerIdx := 0
			progress := 0

			for {
				select {
				case <-done:
					// Clear the line completely
					fmt.Print("\r\033[K")
					// Show completion with full bar (50 chars wide)
					fullBar := green(strings.Repeat("=", 50))
					fmt.Printf("%s %s [%s] %s\n",
						green("→"),
						bold("Update complete"),
						fullBar,
						green("100%"))
					return
				case <-ticker.C:
					// Simulate progress
					if progress < 95 {
						progress += 2
					}

					// Calculate bar components (50 chars wide)
					filledWidth := int(float64(50) * float64(progress) / 100.0)
					emptyWidth := 50 - filledWidth

					// Build ASCII progress bar: [=====> ]
					var bar string
					if filledWidth > 0 {
						bar = blue(strings.Repeat("=", filledWidth-1) + ">") + strings.Repeat(" ", emptyWidth)
					} else {
						bar = strings.Repeat(" ", 50)
					}

					// Show progress
					fmt.Printf("\r%s Updating [%s] %s",
						blue("→"),
						bar,
						yellow(fmt.Sprintf("%d%%", progress)))

					spinnerIdx = (spinnerIdx + 1) % len(spinners)
				}
			}
		}()

		// Run go install command with GOPROXY=direct to bypass cache
		updateResult := exec.Command("go", "install", "github.com/who0xac/pinakastra/cmd/pinakastra@latest")
		updateResult.Env = append(os.Environ(), "GOPROXY=direct")

		// Suppress stdout/stderr
		updateResult.Stdout = nil
		updateResult.Stderr = nil

		err := updateResult.Run()
		done <- true // Stop progress bar
		time.Sleep(200 * time.Millisecond) // Let progress bar finish

		if err != nil {
			fmt.Printf("\n%s %s: %v\n", red("●"), red("Update failed"), err)
			fmt.Printf("\n%s %s\n", yellow("→"), white("Try running manually:"))
			fmt.Printf("   %s\n", white("GOPROXY=direct go install github.com/who0xac/pinakastra/cmd/pinakastra@latest"))
			os.Exit(1)
		}

		fmt.Println()
		fmt.Printf("%s %s\n", green("●"), green("Pinakastra updated successfully!"))
		fmt.Printf("\n%s %s\n", blue("→"), white("Run 'pinakastra version' to verify the update."))
	},
}

func init() {
	// Initialize config directory on first run
	configDir, err := config.EnsureConfigDir()
	if err != nil {
		fmt.Printf("Warning: Failed to create config directory: %v\n", err)
	} else {
		// Initialize default config files
		if err := config.InitializeDefaultConfigs(); err != nil {
			fmt.Printf("Warning: Failed to initialize configs: %v\n", err)
		}
	}
	_ = configDir

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(updateCmd)
	// TODO: Implement these later
	// rootCmd.AddCommand(updateDBCmd)
	// rootCmd.AddCommand(resumeCmd)
	// rootCmd.AddCommand(compareCmd)

	// Required flags
	rootCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "Target domain to scan (required)")
	scanCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain to scan (required)")

	// Scan mode flags
	rootCmd.PersistentFlags().StringVar(&mode, "mode", "standard", "Scan mode [quick|standard|aggressive|stealth]")
	scanCmd.Flags().StringVar(&mode, "mode", "standard", "Scan mode [quick|standard|aggressive|stealth]")

	// AI options
	rootCmd.PersistentFlags().BoolVar(&enableAI, "enable-ai", false, "Enable AI-powered port scanning and deep analysis (default: false)")
	scanCmd.Flags().BoolVar(&enableAI, "enable-ai", false, "Enable AI-powered port scanning and deep analysis (default: false)")

	// Output flags
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Output filename (without extension)")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "json,html", "Output format [json|txt|csv|html|pdf|all]")
	rootCmd.PersistentFlags().StringVar(&outputDir, "output-dir", "./outputs", "Output directory")
	scanCmd.Flags().StringVarP(&output, "output", "o", "", "Output filename (without extension)")
	scanCmd.Flags().StringVarP(&format, "format", "f", "json,html", "Output format [json|txt|csv|html|pdf|all]")
	scanCmd.Flags().StringVar(&outputDir, "output-dir", "./outputs", "Output directory")

	// Performance flags
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 1000, "Concurrent threads")
	rootCmd.PersistentFlags().IntVar(&rateLimit, "rate-limit", 100, "Max requests/second")
	scanCmd.Flags().IntVarP(&threads, "threads", "t", 1000, "Concurrent threads")
	scanCmd.Flags().IntVar(&rateLimit, "rate-limit", 100, "Max requests/second")

	// Subdomain flags
	rootCmd.PersistentFlags().BoolVar(&noBruteforce, "no-bruteforce", false, "Skip DNS brute-forcing")
	scanCmd.Flags().BoolVar(&noBruteforce, "no-bruteforce", false, "Skip DNS brute-forcing")

	// Port scanning flags
	rootCmd.PersistentFlags().StringVarP(&ports, "ports", "p", "80,443,8080,8443,3000,5000,8000,8888", "Ports to scan")
	rootCmd.PersistentFlags().BoolVar(&noPortscan, "no-portscan", false, "Skip port scanning")
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "80,443,8080,8443,3000,5000,8000,8888", "Ports to scan")
	scanCmd.Flags().BoolVar(&noPortscan, "no-portscan", false, "Skip port scanning")

	// Proxy flags
	rootCmd.PersistentFlags().BoolVar(&useTor, "use-tor", false, "Use TOR proxy")
	scanCmd.Flags().BoolVar(&useTor, "use-tor", false, "Use TOR proxy")

	// Custom usage template
	rootCmd.SetUsageTemplate(usageTemplate)

	// Override help command to show colored banner
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printBanner()
		cmd.Print(cmd.UsageString())
	})
}

const usageTemplate = `
USAGE:
  pinakastra -d <domain> [flags]     Scan a target domain
  pinakastra [command]               Run a command

COMMANDS:
  check, c             Check if required tools are installed
  update, u            Update Pinakastra to latest version
  version              Show version information

REQUIRED:
  -d, --domain STRING            Target domain to scan

AI OPTIONS:
  --enable-ai                    Enable AI-powered port scanning and deep analysis (default: false)

OUTPUT:
  -o, --output STRING            Output filename (without extension)
  -f, --format STRING            Output format [json|txt|csv|html|pdf|all] (default: json,html)
  --output-dir STRING            Output directory (default: ./outputs)

PERFORMANCE:
  -t, --threads INT              Concurrent threads (default: 1000)
  --rate-limit INT               Max requests/second (default: 100)

SUBDOMAIN:
  --no-bruteforce                Skip DNS brute-forcing

PORT SCANNING:
  -p, --ports STRING             Ports to scan (default: 80,443,8080,8443,3000,5000,8000,8888)
  --no-portscan                  Skip port scanning

PROXY:
  --use-tor                      Use TOR proxy

EXAMPLES:
  # Basic scan (web security only)
  pinakastra -d target.com

  # Full scan with AI-powered analysis
  pinakastra -d target.com --enable-ai

  # Scan without port scanning
  pinakastra -d target.com --no-portscan

  # Scan through TOR
  pinakastra -d target.com --use-tor

  # Custom output
  pinakastra -d target.com -o my_scan -f json,html,pdf

For more information: https://github.com/who0xac/pinakastra
`

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
