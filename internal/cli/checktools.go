package cli

import (
	"fmt"
	"os/exec"

	"github.com/fatih/color"
)

type CheckResult struct {
	Name      string
	Installed bool
}

func runCheckTools() {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite)
	magenta := color.New(color.FgMagenta, color.Bold)

	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	cyan.Println("                    🔧 TOOL CHECKER")
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// List of all required tools
	requiredTools := []string{
		"amass",
		"subfinder",
		"findomain",
		"assetfinder",
		"sublist3r",
		"chaos",
		"crtsh",
		"shodan",
		"puredns",
		"httpx",
		"dnsx",
		"katana",
		"gau",
		"gf",
		"nuclei",
	}

	results := checkTools(requiredTools)

	installed := 0
	missing := 0
	var missingTools []CheckResult

	for i, result := range results {
		// Progress indicator
		progress := fmt.Sprintf("[%02d/%02d]", i+1, len(results))
		magenta.Printf("%s ", progress)

		if result.Installed {
			green.Print("✓ ")
			cyan.Printf("%-15s", result.Name)
			white.Printf(" │ ")
			green.Println("INSTALLED")
			installed++
		} else {
			red.Print("✗ ")
			cyan.Printf("%-15s", result.Name)
			white.Printf(" │ ")
			red.Println("NOT FOUND")
			missing++
			missingTools = append(missingTools, result)
		}
	}

	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	cyan.Println("                      📊 SUMMARY")
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	white.Print("  Installed   : ")
	green.Printf("%d", installed)
	white.Println(" tools")

	white.Print("  Missing     : ")
	red.Printf("%d", missing)
	white.Println(" tools")

	white.Print("  Total       : ")
	cyan.Printf("%d", len(results))
	white.Println(" tools")

	if missing > 0 {
		fmt.Println()
		yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		yellow.Println("              ⚠️  MISSING TOOLS")
		yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()

		for _, tool := range missingTools {
			red.Printf("  ► %s\n", tool.Name)
		}

		fmt.Println()
		red.Println("  ⚡ Please install missing tools to use all features!")
	} else {
		fmt.Println()
		green.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		green.Println("            ✅ ALL TOOLS INSTALLED - READY TO HACK!")
		green.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}

	fmt.Println()
}

func checkTools(toolNames []string) []CheckResult {
	var results []CheckResult

	for _, name := range toolNames {
		_, err := exec.LookPath(name)
		results = append(results, CheckResult{
			Name:      name,
			Installed: err == nil,
		})
	}

	return results
}
