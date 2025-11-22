package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	domain       string
	outputDir    string
	enableNotify bool
	checkTools   bool
	showHelpFlag bool
)

var rootCmd = &cobra.Command{
	Use:               "pinakastra",
	Short:             "Pinakastra - Automated Reconnaissance Framework",
	DisableFlagParsing: false,
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()

		if showHelpFlag {
			showHelp()
			return
		}

		if checkTools {
			runCheckTools()
			return
		}

		if domain == "" {
			showHelp()
			return
		}
		runScan(cmd, args)
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory")
	rootCmd.Flags().BoolVar(&enableNotify, "nt", false, "Enable notifications")
	rootCmd.Flags().BoolVarP(&checkTools, "check", "c", false, "Check installed tools")
	rootCmd.Flags().BoolVarP(&showHelpFlag, "help", "h", false, "Show help")

	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	rootCmd.DisableFlagsInUseLine = true
}

func showHelp() {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	white := color.New(color.FgWhite)

	fmt.Println()
	yellow.Println("Usage:")
	white.Println("  pinakastra [flags]")
	fmt.Println()

	yellow.Println("Flags:")
	fmt.Printf("  %-20s %s\n", cyan.Sprint("-d, --domain"), "Target domain")
	fmt.Printf("  %-20s %s\n", cyan.Sprint("-o, --output"), "Output directory")
	fmt.Printf("  %-20s %s\n", cyan.Sprint("--nt"), "Enable notifications")
	fmt.Printf("  %-20s %s\n", cyan.Sprint("-c, --check"), "Check installed tools")
	fmt.Printf("  %-20s %s\n", cyan.Sprint("-h, --help"), "Help")
	fmt.Println()

	yellow.Println("Examples:")
	white.Println("  pinakastra -d example.com")
	white.Println("  pinakastra -d example.com --nt")
	white.Println("  pinakastra -d example.com -o /output")
	white.Println("  pinakastra -c")
	fmt.Println()
}

