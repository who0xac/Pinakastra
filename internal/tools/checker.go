package tools

import (
	"os/exec"
	"strings"
)

type CheckResult struct {
	Name      string
	Installed bool
	Version   string
}

type Checker struct {
	tools []ToolCheck
}

type ToolCheck struct {
	Name       string
	Command    string
	VersionArg string
}

func NewChecker() *Checker {
	return &Checker{
		tools: []ToolCheck{
			// Subdomain Enumeration
			{Name: "amass", Command: "amass", VersionArg: "version"},
			{Name: "subfinder", Command: "subfinder", VersionArg: "-version"},
			{Name: "findomain", Command: "findomain", VersionArg: "--version"},
			{Name: "assetfinder", Command: "assetfinder", VersionArg: "-h"},
			{Name: "sublist3r", Command: "sublist3r", VersionArg: "-h"},
			{Name: "crtsh", Command: "crtsh", VersionArg: "-h"},

			// HTTP Probing
			{Name: "httpx", Command: "httpx", VersionArg: "-version"},

			// Content Discovery
			{Name: "ffuf", Command: "ffuf", VersionArg: "-V"},
			{Name: "dirsearch", Command: "dirsearch", VersionArg: "--version"},

			// Recon & OSINT
			{Name: "shodan", Command: "shodan", VersionArg: "version"},

			// DNS Tools
			{Name: "puredns", Command: "puredns", VersionArg: "version"},
			{Name: "massdns", Command: "massdns", VersionArg: "--help"},
			{Name: "dnsx", Command: "dnsx", VersionArg: "-version"},

			// URL Discovery
			{Name: "gau", Command: "gau", VersionArg: "-version"},
			{Name: "katana", Command: "katana", VersionArg: "-version"},
			{Name: "hakrawler", Command: "hakrawler", VersionArg: "-h"},
			{Name: "subjs", Command: "subjs", VersionArg: "-h"},

			// Parameter Discovery
			{Name: "arjun", Command: "arjun", VersionArg: "--version"},

			// Screenshots
			{Name: "gowitness", Command: "gowitness", VersionArg: "version"},

			// Subdomain Takeover
			{Name: "subzy", Command: "subzy", VersionArg: "-h"},

			// Secret Finding
			{Name: "secretfinder", Command: "secretfinder", VersionArg: "-h"},

			// Chaos (ProjectDiscovery)
			{Name: "chaos", Command: "chaos", VersionArg: "-version"},

			// Port Scanning
			{Name: "nmap", Command: "nmap", VersionArg: "--version"},

			// Vulnerability Scanning
			{Name: "nuclei", Command: "nuclei", VersionArg: "-version"},

			// Utils
			{Name: "gf", Command: "gf", VersionArg: "-h"},
			{Name: "jq", Command: "jq", VersionArg: "--version"},
		},
	}
}

func (c *Checker) CheckAll() []CheckResult {
	var results []CheckResult

	for _, tool := range c.tools {
		result := CheckResult{
			Name: tool.Name,
		}

		path, err := exec.LookPath(tool.Command)
		if err != nil {
			result.Installed = false
		} else {
			result.Installed = true
			result.Version = c.getVersion(path, tool.VersionArg)
		}

		results = append(results, result)
	}

	return results
}

func (c *Checker) Check(name string) *CheckResult {
	for _, tool := range c.tools {
		if tool.Name == name {
			result := &CheckResult{
				Name: tool.Name,
			}

			path, err := exec.LookPath(tool.Command)
			if err != nil {
				result.Installed = false
			} else {
				result.Installed = true
				result.Version = c.getVersion(path, tool.VersionArg)
			}

			return result
		}
	}

	return nil
}

func (c *Checker) getVersion(path, versionArg string) string {
	if versionArg == "" {
		return "installed"
	}

	cmd := exec.Command(path, versionArg)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "installed"
	}

	version := strings.TrimSpace(string(output))
	lines := strings.Split(version, "\n")
	if len(lines) > 0 {
		return lines[0]
	}

	return "installed"
}

func (c *Checker) GetMissing() []CheckResult {
	var missing []CheckResult
	for _, result := range c.CheckAll() {
		if !result.Installed {
			missing = append(missing, result)
		}
	}
	return missing
}

func (c *Checker) GetInstalled() []CheckResult {
	var installed []CheckResult
	for _, result := range c.CheckAll() {
		if result.Installed {
			installed = append(installed, result)
		}
	}
	return installed
}
