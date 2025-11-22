package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	domain       string
	outputDir    string
	enableNotify bool
)

var rootCmd = &cobra.Command{
	Use:   "pinakastra",
	Short: "Pinakastra",
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
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
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")

	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory")
	rootCmd.Flags().BoolVar(&enableNotify, "nt", false, "Enable notifications")

	checkToolsCmd.Aliases = []string{"c"}
	webuiCmd.Aliases = []string{"w"}

	rootCmd.AddCommand(checkToolsCmd)
	rootCmd.AddCommand(webuiCmd)

	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
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
	fmt.Printf("  %-20s %s\n", cyan.Sprint("-c"), "Check tools")
	fmt.Printf("  %-20s %s\n", cyan.Sprint("-w"), "Start web UI")
	fmt.Printf("  %-20s %s\n", cyan.Sprint("-p, --port"), "Web UI port (default: 9000)")
	fmt.Printf("  %-20s %s\n", cyan.Sprint("-h, --help"), "Help")
	fmt.Println()

	yellow.Println("Examples:")
	white.Println("  pinakastra -d example.com")
	white.Println("  pinakastra -d example.com --nt")
	white.Println("  pinakastra -d example.com -o /output")
	white.Println("  pinakastra -c")
	white.Println("  pinakastra -w -p 8080")
	fmt.Println()
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("$HOME/.pinakastra")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Printf("Error reading config: %s\n", err)
		}
	}
}
