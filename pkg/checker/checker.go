package checker

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/fatih/color"
)

// Tool represents an external tool requirement
type Tool struct {
	Name        string
	Command     string
	Required    bool
	Description string
	InstallURL  string
}

// ToolStatus represents the installation status of a tool
type ToolStatus struct {
	Tool      Tool
	Installed bool
	Version   string
	Path      string
}

// GetRequiredTools returns the list of tools used by Pinakastra
func GetRequiredTools() []Tool {
	return []Tool{
		{
			Name:        "subfinder",
			Command:     "subfinder",
			Required:    true,
			Description: "Subdomain enumeration",
			InstallURL:  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		},
		{
			Name:        "httpx",
			Command:     "httpx",
			Required:    true,
			Description: "HTTP probing",
			InstallURL:  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
		},
		{
			Name:        "dnsx",
			Command:     "dnsx",
			Required:    true,
			Description: "DNS resolution",
			InstallURL:  "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		},
		{
			Name:        "katana",
			Command:     "katana",
			Required:    true,
			Description: "Web crawling",
			InstallURL:  "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		},
		{
			Name:        "gau",
			Command:     "gau",
			Required:    true,
			Description: "URL discovery",
			InstallURL:  "go install github.com/lc/gau/v2/cmd/gau@latest",
		},
		{
			Name:        "puredns",
			Command:     "puredns",
			Required:    true,
			Description: "DNS bruteforce",
			InstallURL:  "go install github.com/d3mondev/puredns/v2@latest",
		},
		{
			Name:        "findomain",
			Command:     "findomain",
			Required:    true,
			Description: "Subdomain enumeration",
			InstallURL:  "https://github.com/Findomain/Findomain/releases",
		},
		{
			Name:        "assetfinder",
			Command:     "assetfinder",
			Required:    true,
			Description: "Subdomain enumeration",
			InstallURL:  "go install github.com/tomnomnom/assetfinder@latest",
		},
		{
			Name:        "chaos",
			Command:     "chaos",
			Required:    true,
			Description: "Subdomain enumeration",
			InstallURL:  "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
		},
		{
			Name:        "nmap",
			Command:     "nmap",
			Required:    true,
			Description: "Port scanning",
			InstallURL:  "sudo apt install nmap",
		},
		{
			Name:        "sublist3r",
			Command:     "sublist3r",
			Required:    true,
			Description: "Subdomain enumeration",
			InstallURL:  "pip install sublist3r",
		},
		{
			Name:        "crtsh",
			Command:     "crtsh",
			Required:    true,
			Description: "Certificate transparency",
			InstallURL:  "go install github.com/cemulus/crtsh@latest",
		},
		{
			Name:        "shodan",
			Command:     "shodan",
			Required:    true,
			Description: "Shodan search",
			InstallURL:  "pip install shodan",
		},
	}
}

// CheckTool checks if a tool is installed
func CheckTool(tool Tool) ToolStatus {
	status := ToolStatus{
		Tool:      tool,
		Installed: false,
	}

	// Check if command exists
	path, err := exec.LookPath(tool.Command)
	if err != nil {
		return status
	}

	status.Installed = true
	status.Path = path

	// Try to get version
	version := getToolVersion(tool.Command)
	status.Version = version

	return status
}

// getToolVersion attempts to get the version of a tool
func getToolVersion(command string) string {
	// Try common version flags
	versionFlags := []string{"-version", "--version", "-v", "version"}

	for _, flag := range versionFlags {
		cmd := exec.Command(command, flag)
		output, err := cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			// Get first line of output
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				version := strings.TrimSpace(lines[0])
				// Limit to 80 characters
				if len(version) > 80 {
					version = version[:80] + "..."
				}
				return version
			}
		}
	}

	return "installed"
}

// CheckAllTools checks all required tools
func CheckAllTools() []ToolStatus {
	tools := GetRequiredTools()
	statuses := make([]ToolStatus, len(tools))

	for i, tool := range tools {
		statuses[i] = CheckTool(tool)
	}

	return statuses
}

// Color functions using fatih/color
var (
	Blue   = color.New(color.FgCyan).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
	Green  = color.New(color.FgGreen).SprintFunc()
	Red    = color.New(color.FgRed).SprintFunc()
	White  = color.New(color.FgWhite).SprintFunc()
	Bold   = color.New(color.Bold).SprintFunc()
)

// PrintToolStatus prints the status of all tools
func PrintToolStatus() {
	fmt.Printf("%s %s\n", Blue("→"), Bold("Checking installed tools..."))
	fmt.Println()

	statuses := CheckAllTools()

	installed := 0
	total := len(statuses)

	// Print all tools (all are required now)
	fmt.Println(Bold("REQUIRED TOOLS:"))
	for _, status := range statuses {
		if status.Installed {
			installed++
			fmt.Printf("  %s %-15s %s\n",
				Green("●"),
				Blue(status.Tool.Name),
				White(status.Version))
		} else {
			fmt.Printf("  %s %-15s %s\n",
				Red("●"),
				Blue(status.Tool.Name),
				Red("NOT INSTALLED"))
			fmt.Printf("     %s %s\n",
				Yellow("→"),
				White("Install: "+status.Tool.InstallURL))
		}
	}

	// Print summary
	fmt.Println()
	fmt.Println(Blue(strings.Repeat("━", 60)))

	if installed == total {
		fmt.Printf("%s %s/%d %s\n",
			Bold("SUMMARY:"),
			Green(fmt.Sprintf("%d", installed)),
			total,
			Green("tools installed"))
	} else {
		fmt.Printf("%s %s/%d %s\n",
			Bold("SUMMARY:"),
			Yellow(fmt.Sprintf("%d", installed)),
			total,
			Yellow("tools installed"))
	}

	fmt.Println(Blue(strings.Repeat("━", 60)))

	if installed < total {
		fmt.Println()
		fmt.Printf("%s %s\n", Yellow("⚠"), Yellow("WARNING: Some required tools are missing!"))
		fmt.Printf("   %s\n", White("Pinakastra may not work correctly without them."))
		fmt.Println()
	} else {
		fmt.Println()
		fmt.Printf("%s %s\n", Green("●"), Green("All required tools are installed!"))
		fmt.Println()
	}

	// Print Go installation check
	fmt.Printf("%s %s\n", Blue("→"), Bold("Checking Go installation..."))
	goPath, err := exec.LookPath("go")
	if err != nil {
		fmt.Printf("  %s %s\n", Red("●"), Red("Go is NOT installed"))
		fmt.Printf("     %s %s\n", Yellow("→"), White("Install: https://go.dev/dl/"))
	} else {
		cmd := exec.Command("go", "version")
		output, _ := cmd.Output()
		version := strings.TrimSpace(string(output))
		fmt.Printf("  %s %s\n", Green("●"), White(version))
		fmt.Printf("     %s %s\n", Blue("→"), White("Path: "+goPath))
	}

	// Print OS info
	fmt.Println()
	fmt.Printf("%s %s: %s\n",
		Blue("→"),
		Bold("Operating System"),
		White(fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)))
}

// IsToolInstalled checks if a specific tool is installed
func IsToolInstalled(toolName string) bool {
	tools := GetRequiredTools()
	for _, tool := range tools {
		if tool.Name == toolName {
			status := CheckTool(tool)
			return status.Installed
		}
	}
	return false
}
