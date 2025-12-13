package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	pinakastra "github.com/who0xac/pinakastra"
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

🔱 The Ultimate Security Assessment Tool 🔱
AI-Powered Attack Surface Discovery & Analysis

Version: %s
Author: %s

`
)

var (
	// Global flags
	domain    string
	mode      string
	enableAI  bool
	aiDeep    bool
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

	// Web UI flags
	webUI   bool
	webPort int
)

var rootCmd = &cobra.Command{
	Use:   "pinakastra",
	Short: "🔱 AI-Powered Attack Surface Discovery & Analysis",
	Long:  fmt.Sprintf(banner, version, author),
	Run: func(cmd *cobra.Command, args []string) {
		// If no command specified, show help
		if domain == "" {
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

		fmt.Printf(banner, version, author)
		fmt.Printf("Target: %s\n", domain)
		fmt.Printf("AI Analysis: %v\n", enableAI)
		fmt.Printf("Web UI: %v\n", webUI)
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
			AIDeep:        aiDeep,
			Threads:       threads,
			RateLimit:     rateLimit,
			UseTor:        useTor,
			NoBruteforce:  noBruteforce,
			NoPortscan:    noPortscan,
			Ports:         ports,
			WebUI:         webUI,
			WebPort:       webPort,
		}

		// Create scanner and run
		s := scanner.NewScanner(config, pinakastra.WebFiles)
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
		fmt.Printf(banner, version, author)
	},
}

var checkCmd = &cobra.Command{
	Use:     "check",
	Aliases: []string{"c"},
	Short:   "Check if required tools are installed",
	Long:    "Verify that all required external tools are installed and accessible",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(banner, version, author)
		fmt.Println()
		checker.PrintToolStatus()
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
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(checkCmd)
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
	rootCmd.PersistentFlags().BoolVar(&enableAI, "enable-ai", true, "Enable AI analysis")
	rootCmd.PersistentFlags().BoolVar(&aiDeep, "ai-deep", false, "Deep AI analysis (slower, more accurate)")
	scanCmd.Flags().BoolVar(&enableAI, "enable-ai", true, "Enable AI analysis")
	scanCmd.Flags().BoolVar(&aiDeep, "ai-deep", false, "Deep AI analysis (slower, more accurate)")

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

	// Web UI flags
	rootCmd.PersistentFlags().BoolVar(&webUI, "web-ui", true, "Enable web dashboard")
	rootCmd.PersistentFlags().IntVar(&webPort, "web-port", 8888, "Web UI port")
	scanCmd.Flags().BoolVar(&webUI, "web-ui", true, "Enable web dashboard")
	scanCmd.Flags().IntVar(&webPort, "web-port", 8888, "Web UI port")

	// Custom usage template
	rootCmd.SetUsageTemplate(usageTemplate)
}

const usageTemplate = `
USAGE:
  pinakastra [command] [flags]

COMMANDS:
  scan                 Scan a target domain (default)
  check, c             Check if required tools are installed
  version              Show version information

REQUIRED:
  -d, --domain STRING            Target domain to scan

AI OPTIONS:
  --enable-ai                    Enable AI analysis (default: true)
  --ai-deep                      Deep AI with active exploitation (Nuclei + AI payloads)

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

WEB UI:
  --web-ui                       Enable web dashboard (default: true)
  --web-port INT                 Web UI port (default: 8888)

EXAMPLES:
  # Basic scan
  pinakastra -d target.com

  # Scan with AI exploitation
  pinakastra -d target.com --ai-deep

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
