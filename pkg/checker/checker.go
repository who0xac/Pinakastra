package checker

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
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
			Name:        "katana",
			Command:     "katana",
			Required:    true,
			Description: "Web crawling",
			InstallURL:  "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		},
		{
			Name:        "gau",
			Command:     "gau",
			Required:    false,
			Description: "URL discovery from archives",
			InstallURL:  "go install github.com/lc/gau/v2/cmd/gau@latest",
		},
		{
			Name:        "waybackurls",
			Command:     "waybackurls",
			Required:    false,
			Description: "Wayback Machine URLs",
			InstallURL:  "go install github.com/tomnomnom/waybackurls@latest",
		},
		{
			Name:        "puredns",
			Command:     "puredns",
			Required:    false,
			Description: "DNS bruteforcing",
			InstallURL:  "go install github.com/d3mondev/puredns/v2@latest",
		},
		{
			Name:        "assetfinder",
			Command:     "assetfinder",
			Required:    false,
			Description: "Additional subdomain enumeration",
			InstallURL:  "go install github.com/tomnomnom/assetfinder@latest",
		},
		{
			Name:        "amass",
			Command:     "amass",
			Required:    false,
			Description: "Advanced subdomain enumeration",
			InstallURL:  "https://github.com/OWASP/Amass",
		},
		{
			Name:        "nmap",
			Command:     "nmap",
			Required:    false,
			Description: "Port scanning",
			InstallURL:  "https://nmap.org/download.html",
		},
		{
			Name:        "nuclei",
			Command:     "nuclei",
			Required:    false,
			Description: "Vulnerability scanning",
			InstallURL:  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		},
		{
			Name:        "dnsx",
			Command:     "dnsx",
			Required:    false,
			Description: "DNS resolution",
			InstallURL:  "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
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

// PrintToolStatus prints the status of all tools
func PrintToolStatus() {
	fmt.Println("🔍 Checking installed tools...")
	fmt.Println()

	statuses := CheckAllTools()

	requiredInstalled := 0
	requiredTotal := 0
	optionalInstalled := 0
	optionalTotal := 0

	// Print required tools
	fmt.Println("📋 REQUIRED TOOLS:")
	for _, status := range statuses {
		if !status.Tool.Required {
			continue
		}
		requiredTotal++

		if status.Installed {
			requiredInstalled++
			fmt.Printf("  ✅ %-15s %s\n", status.Tool.Name, status.Version)
		} else {
			fmt.Printf("  ❌ %-15s NOT INSTALLED\n", status.Tool.Name)
			fmt.Printf("     Install: %s\n", status.Tool.InstallURL)
		}
	}

	fmt.Println()
	fmt.Println("🔧 OPTIONAL TOOLS:")
	for _, status := range statuses {
		if status.Tool.Required {
			continue
		}
		optionalTotal++

		if status.Installed {
			optionalInstalled++
			fmt.Printf("  ✅ %-15s %s\n", status.Tool.Name, status.Version)
		} else {
			fmt.Printf("  ⚠️  %-15s NOT INSTALLED\n", status.Tool.Name)
			fmt.Printf("     Install: %s\n", status.Tool.InstallURL)
		}
	}

	// Print summary
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📊 SUMMARY: %d/%d required tools installed\n", requiredInstalled, requiredTotal)
	fmt.Printf("           %d/%d optional tools installed\n", optionalInstalled, optionalTotal)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if requiredInstalled < requiredTotal {
		fmt.Println()
		fmt.Println("⚠️  WARNING: Some required tools are missing!")
		fmt.Println("   Pinakastra may not work correctly without them.")
		fmt.Println()
	} else {
		fmt.Println()
		fmt.Println("✅ All required tools are installed!")
		fmt.Println()
	}

	// Print Go installation check
	fmt.Println("🔍 Checking Go installation...")
	goPath, err := exec.LookPath("go")
	if err != nil {
		fmt.Println("  ❌ Go is NOT installed")
		fmt.Println("     Install: https://go.dev/dl/")
	} else {
		cmd := exec.Command("go", "version")
		output, _ := cmd.Output()
		version := strings.TrimSpace(string(output))
		fmt.Printf("  ✅ %s\n", version)
		fmt.Printf("     Path: %s\n", goPath)
	}

	// Print OS info
	fmt.Println()
	fmt.Printf("💻 Operating System: %s/%s\n", runtime.GOOS, runtime.GOARCH)
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
