package terminal

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Colors
var (
	Blue    = color.New(color.FgCyan).SprintFunc()
	Cyan    = color.New(color.FgCyan).SprintFunc() // Alias for Blue
	Yellow  = color.New(color.FgYellow).SprintFunc()
	Green   = color.New(color.FgGreen).SprintFunc()
	Red     = color.New(color.FgRed).SprintFunc()
	White   = color.New(color.FgWhite).SprintFunc()
	Gray    = color.New(color.FgHiBlack).SprintFunc()
	Bold    = color.New(color.Bold).SprintFunc()
	Magenta = color.New(color.FgMagenta).SprintFunc()
)

// PrintSectionHeader prints a section header with arrows
func PrintSectionHeader(title string) {
	arrows := strings.Repeat("→", 75)
	fmt.Println()
	fmt.Println(Blue(arrows))
	fmt.Printf("%s%s%s\n", strings.Repeat(" ", 25), Bold(title), strings.Repeat(" ", 25))
	fmt.Println(Blue(arrows))
	fmt.Println()
}

// ToolStatus represents the status of a tool
type ToolStatus struct {
	Name      string
	Status    string // "starting", "running", "completed", "failed"
	Count     int
	Duration  time.Duration
	StartTime time.Time
}

// PrintToolStarting prints when a tool starts (does nothing - tools print directly)
func PrintToolStarting(toolName string, message ...string) {
	// Empty - tools will print their own status
}

// PrintToolRunning updates the tool status on the same line with spinner and elapsed time
func PrintToolRunning(toolName string, spinner string, elapsed time.Duration, progress string) {
	minutes := int(elapsed.Minutes())
	seconds := int(elapsed.Seconds()) % 60

	if progress != "" {
		fmt.Printf("\r%s %s is running... %s %s %dm %ds",
			Yellow("●"),
			Blue(toolName),
			Yellow(spinner),
			Yellow(progress),
			minutes,
			seconds)
	} else {
		fmt.Printf("\r%s %s is running... %s %dm %ds",
			Yellow("●"),
			Blue(toolName),
			Yellow(spinner),
			minutes,
			seconds)
	}
}

// PrintToolCompleted prints when a tool completes successfully (clears line first)
func PrintToolCompleted(toolName string, count int, duration time.Duration) {
	fmt.Printf("\r\033[K%s %s enumeration complete [%s found] %s\n",
		Green("●"),
		Blue(toolName),
		Yellow(fmt.Sprintf("%d", count)),
		White(fmt.Sprintf("(%.1fs)", duration.Seconds())))
}

// PrintToolFailed prints when a tool fails (clears line first)
func PrintToolFailed(toolName string, err error, duration time.Duration) {
	fmt.Printf("\r\033[K%s %s failed: %v %s\n",
		Red("●"),
		Blue(toolName),
		Yellow(fmt.Sprintf("%v", err)),
		White(fmt.Sprintf("(%.1fs)", duration.Seconds())))
}

// PrintSubdomainSummary prints the final subdomain enumeration summary with tree structure
func PrintSubdomainSummary(total, duplicates, unique int) {
	fmt.Println()
	fmt.Println(Bold("Subdomain Enumeration Summary:"))
	fmt.Printf("   ├── Total subdomains found: %s\n", Green(fmt.Sprintf("%d", total)))
	fmt.Printf("   ├── Duplicates removed: %s\n", Yellow(fmt.Sprintf("%d", duplicates)))
	fmt.Printf("   └── Unique subdomains: %s\n", Bold(Green(fmt.Sprintf("%d", unique))))
	fmt.Println()
}

// PrintProgress prints a simple progress message
func PrintProgress(message string) {
	fmt.Printf("%s %s\n", Blue("→"), message)
}

// PrintProgressWithSpinner prints progress with a spinning indicator
func PrintProgressWithSpinner(message string, step int) {
	spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinner := spinners[step%len(spinners)]
	fmt.Printf("\r%s %s", Blue(spinner), message)
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	fmt.Printf("%s %s\n", Green("✓"), message)
}

// PrintWarning prints a warning message
func PrintWarning(message string) {
	fmt.Printf("%s %s\n", Yellow("⚠"), message)
}

// PrintError prints an error message
func PrintError(message string) {
	fmt.Printf("%s %s\n", Red("✗"), message)
}

// ClearLine clears the current line
func ClearLine() {
	fmt.Print("\r\033[K")
}

// PrintToolStartingWithWarning prints when a tool starts with a warning message
func PrintToolStartingWithWarning(toolName, warning string) {
	fmt.Printf("%s %s is running (%s)", Blue("●"), toolName, Yellow(warning))
}

// PrintToolProgress prints tool progress with live counter
func PrintToolProgress(toolName string, current, total int) {
	// Move cursor to beginning of line and clear it
	fmt.Printf("\r\033[K")

	// Calculate percentage
	percentage := float64(current) / float64(total) * 100

	// Show progress with counter
	fmt.Printf("%s %s is running [%d/%d - %.1f%%]",
		Yellow("●"), toolName, current, total, percentage)
}

// PrintHTTPProbeSummary prints the HTTP probing summary with tree structure
func PrintHTTPProbeSummary(totalProbed, liveCount int) {
	fmt.Println()
	fmt.Println(Bold("HTTP Probing Summary:"))
	fmt.Printf("   ├── Total subdomains probed: %s\n", Green(fmt.Sprintf("%d", totalProbed)))
	fmt.Printf("   └── Live URLs found: %s\n", Bold(Green(fmt.Sprintf("%d", liveCount))))
	fmt.Println()
}

// PrintIPResolutionSummary prints the IP resolution summary with tree structure
func PrintIPResolutionSummary(totalHosts, resolvedCount int) {
	fmt.Println()
	fmt.Println(Bold("IP Resolution Summary:"))
	fmt.Printf("   ├── Total hosts: %s\n", Green(fmt.Sprintf("%d", totalHosts)))
	fmt.Printf("   └── IPs resolved: %s\n", Bold(Green(fmt.Sprintf("%d", resolvedCount))))
	fmt.Println()
}

// PrintURLDiscoverySummary prints the URL discovery summary with tree structure
func PrintURLDiscoverySummary(liveURLs, katanaURLs, gauURLs, totalURLs int) {
	fmt.Println()
	fmt.Println(Bold("URL Discovery Summary:"))
	fmt.Printf("   ├── Live URLs (httpx): %s\n", Green(fmt.Sprintf("%d", liveURLs)))
	fmt.Printf("   ├── Katana URLs: %s\n", Green(fmt.Sprintf("%d", katanaURLs)))
	fmt.Printf("   ├── GAU URLs: %s\n", Green(fmt.Sprintf("%d", gauURLs)))
	fmt.Printf("   └── Unique URLs (merged): %s\n", Bold(Green(fmt.Sprintf("%d", totalURLs))))
	fmt.Println()
}

// PrintPhaseStarting prints when a phase starts
func PrintPhaseStarting(phaseName string) {
	fmt.Printf("\n%s %s...\n", Blue("→"), phaseName)
}

// PrintToolSkipped prints when a tool is skipped
func PrintToolSkipped(toolName, reason string) {
	fmt.Printf("%s %s skipped (%s)\n", Yellow("○"), toolName, reason)
}

// PrintPortScanSummary prints the port scanning summary with tree structure
func PrintPortScanSummary(totalHosts, openPorts, servicesWithCVEs int) {
	fmt.Println()
	fmt.Println(Bold("Port Scanning Summary:"))
	fmt.Printf("   ├── Total hosts scanned: %s\n", Green(fmt.Sprintf("%d", totalHosts)))
	fmt.Printf("   ├── Open ports found: %s\n", Green(fmt.Sprintf("%d", openPorts)))
	fmt.Printf("   └── Services with CVEs: %s\n", Bold(Red(fmt.Sprintf("%d", servicesWithCVEs))))
	fmt.Println()
}

// PrintCVEFound prints when a CVE is discovered
func PrintCVEFound(ip string, port int, service, cveID, severity string) {
	severityColor := Yellow
	if severity == "CRITICAL" || severity == "HIGH" {
		severityColor = Red
	}
	fmt.Printf("   %s %s:%d (%s) - %s [%s]\n",
		Red("!"), ip, port, service, cveID, severityColor(severity))
}

// ASNDisplayInfo contains ASN information for display
type ASNDisplayInfo struct {
	ASN         string
	Description string
	Country     string
	IPCount     int
	SampleIPs   []string
}

// PrintASNSummary prints the ASN distribution summary with enhanced format
func PrintASNSummary(totalASNs int, topASNs []string) {
	if totalASNs == 0 {
		return
	}

	fmt.Println()
	PrintSectionDivider()
	fmt.Printf("\n%s %s\n\n", Blue("→"), Bold("ASN/CIDR EXPANSION"))
	fmt.Printf("   %s Discovered %s unique ASNs across multiple IPs\n\n",
		Green("✓"),
		Cyan(fmt.Sprintf("%d", totalASNs)))

	// Show top ASNs
	for i, asn := range topASNs {
		if i >= 10 { // Show top 10
			break
		}
		fmt.Printf("   %s %s\n", Blue("→"), Green(asn))
	}

	if len(topASNs) > 10 {
		fmt.Printf("\n   %s ...and %s more ASNs\n", Yellow("⚠"), Yellow(fmt.Sprintf("%d", len(topASNs)-10)))
	}
	fmt.Println()
}

// PrintASNSummaryDetailed prints the detailed ASN distribution with country and IPs
func PrintASNSummaryDetailed(asnInfos []ASNDisplayInfo, totalIPs int) {
	if len(asnInfos) == 0 {
		return
	}

	fmt.Printf("\n%s %s\n", Blue("→"), Bold("ASN/CIDR EXPANSION"))
	fmt.Printf("   %s Discovered %s unique ASNs across %s IPs\n",
		Green("✓"),
		Cyan(fmt.Sprintf("%d", len(asnInfos))),
		Cyan(fmt.Sprintf("%d", totalIPs)))

	// Show ALL ASNs (no limit)
	for _, info := range asnInfos {
		// Format: AS[Country] - Description [Sample IPs]
		country := info.Country
		if country == "" {
			country = "Unknown"
		}

		// Print ASN header without IPs
		fmt.Printf("   %s %s - %s\n",
			Yellow(fmt.Sprintf("AS%s%s", country, info.ASN)),
			Blue(fmt.Sprintf("(%d IPs)", info.IPCount)),
			Green(info.Description))

		// Show IPs on separate indented lines (max 8 IPs per line for readability)
		if len(info.SampleIPs) > 0 {
			ipsPerLine := 8
			totalLines := (len(info.SampleIPs) + ipsPerLine - 1) / ipsPerLine

			for j := 0; j < len(info.SampleIPs); j += ipsPerLine {
				end := j + ipsPerLine
				if end > len(info.SampleIPs) {
					end = len(info.SampleIPs)
				}

				ipLine := strings.Join(info.SampleIPs[j:end], ", ")

				// Add [ for first line, ] for last line
				lineNum := j / ipsPerLine
				if lineNum == 0 && totalLines == 1 {
					// Single line - add both brackets
					fmt.Printf("      %s\n", White("["+ipLine+"]"))
				} else if lineNum == 0 {
					// First line of multiple
					fmt.Printf("      %s\n", White("["+ipLine+","))
				} else if lineNum == totalLines-1 {
					// Last line
					fmt.Printf("      %s\n", White(ipLine+"]"))
				} else {
					// Middle lines
					fmt.Printf("      %s\n", White(ipLine+","))
				}
			}
		}
	}
	fmt.Println()
}

// PrintVHostSummary prints the virtual host discovery summary
func PrintVHostSummary(totalVHosts, totalIPs int) {
	if totalVHosts == 0 {
		return
	}

	fmt.Println()
	fmt.Println(Bold("Virtual Host Discovery:"))
	fmt.Printf("   ├── IPs with VHosts: %s\n", Green(fmt.Sprintf("%d", totalIPs)))
	fmt.Printf("   └── Total VHosts found: %s\n", Bold(Green(fmt.Sprintf("%d", totalVHosts))))
	fmt.Println()
}

// PrintVHostFound prints when a vhost is discovered
func PrintVHostFound(ip, vhost string) {
	fmt.Printf("   %s %s → %s\n", Blue("→"), ip, Green(vhost))
}

// ===== ADDITIONAL DISPLAY FUNCTIONS =====

// PrintInfo prints an informational message
func PrintInfo(message string) {
	fmt.Printf("%s %s\n", Blue("ℹ"), message)
}

// PrintAlert prints an alert message
func PrintAlert(message string) {
	fmt.Printf("%s %s\n", Red("⚠"), Red(message))
}

// PrintSectionDivider prints a section divider
func PrintSectionDivider() {
	fmt.Println(strings.Repeat("─", 80))
}

// PrintCVEHeader prints CVE information prominently
func PrintCVEHeader(cveID, name, severity, url, endpoint string, cweIDs []string, references []string) {
	fmt.Println()
	PrintSectionDivider()

	// Main CVE header with severity color
	severityColor := Red
	if severity == "high" {
		severityColor = Yellow
	} else if severity == "medium" {
		severityColor = Yellow
	}

	fmt.Printf("\n%s %s (%s) - %s\n\n",
		Red("🔴"),
		Bold(cveID),
		name,
		severityColor(strings.ToUpper(severity)))

	// Details
	fmt.Printf("   ├── CVE: %s\n", Yellow(cveID))
	fmt.Printf("   ├── Severity: %s\n", severityColor(strings.ToUpper(severity)))

	if len(cweIDs) > 0 {
		fmt.Printf("   ├── CWE: %s\n", Yellow(strings.Join(cweIDs, ", ")))
	}

	fmt.Printf("   ├── Target: %s\n", Green(url))
	fmt.Printf("   ├── Endpoint: %s\n", Blue(endpoint))

	if len(references) > 0 && len(references) <= 3 {
		fmt.Printf("   └── References:\n")
		for _, ref := range references {
			fmt.Printf("       - %s\n", Blue(ref))
		}
	} else if len(references) > 3 {
		fmt.Printf("   └── References: (%d available)\n", len(references))
		for i := 0; i < 2; i++ {
			fmt.Printf("       - %s\n", Blue(references[i]))
		}
		fmt.Printf("       - ... and %d more\n", len(references)-2)
	} else {
		fmt.Printf("   └── No references available\n")
	}

	fmt.Println()
}

// PrintVulnHeader prints non-CVE vulnerability header
func PrintVulnHeader(name, severity, url, endpoint string, index, total int) {
	fmt.Println()

	severityColor := Red
	if severity == "high" {
		severityColor = Yellow
	} else if severity == "medium" {
		severityColor = Yellow
	} else if severity == "low" {
		severityColor = White
	}

	fmt.Printf("[EXPLOIT %d/%d] %s - %s\n",
		index,
		total,
		Bold(name),
		severityColor(strings.ToUpper(severity)))

	fmt.Printf("   ├── URL: %s\n", Green(url))
	fmt.Printf("   └── Endpoint: %s\n", Blue(endpoint))
	fmt.Println()
}

// PrintAIDecision prints AI decision with reasoning
func PrintAIDecision(decision, reasoning string) {
	fmt.Printf("[AI-2] Decision: %s (%s)\n", Bold(decision), reasoning)
}

// PrintAIDecisionResult prints if AI decision was right or wrong
func PrintAIDecisionResult(success bool, technique string) {
	if success {
		fmt.Printf("[AI-2] %s Decision was RIGHT - %s worked\n", Green("✓"), technique)
		fmt.Printf("[AI-2] Learning: Saving successful technique for similar targets\n")
	} else {
		fmt.Printf("[AI-2] %s Decision was WRONG - %s blocked\n", Red("✗"), technique)
		fmt.Printf("[AI-2] Learning: Marking %s as ineffective for this target\n", technique)
	}
}

// PrintExploitAttempt prints a single exploit attempt
func PrintExploitAttempt(attemptNum, maxAttempts int, payload, status string) {
	statusSymbol := Yellow("●")
	if status == "SUCCESS" {
		statusSymbol = Green("✓")
	} else if status == "BLOCKED" {
		statusSymbol = Red("✗")
	}

	fmt.Printf("   %s Attempt %d/%d: %s → %s\n",
		statusSymbol,
		attemptNum,
		maxAttempts,
		payload,
		status)
}

// PrintExploitSuccess prints successful exploitation
func PrintExploitSuccess(message string, timeElapsed string) {
	fmt.Printf("\n   %s EXPLOIT SUCCESSFUL - %s\n", Green("✓"), message)
	fmt.Printf("   Time elapsed: %s\n\n", timeElapsed)
}

// PrintExploitFailed prints failed exploitation
func PrintExploitFailed(reason string, timeElapsed string) {
	fmt.Printf("\n   %s EXPLOIT FAILED - %s\n", Red("✗"), reason)
	fmt.Printf("   Time elapsed: %s\n\n", timeElapsed)
}

// PrintExploitTimeout prints timeout message
func PrintExploitTimeout(timeLimit string) {
	fmt.Printf("   %s TIMEOUT: Max time exceeded (%s) - Skipping to next\n\n", Yellow("⚠"), timeLimit)
}

// PrintExploitSkipped prints when a vulnerability is skipped
func PrintExploitSkipped(reason string) {
	fmt.Printf("   %s SKIPPED: %s\n\n", Yellow("○"), reason)
}

// PrintFinalIntelligenceSummary prints the final intelligence summary for all subdomains
func PrintFinalIntelligenceSummary(subdomains []SubdomainIntel) {
	if len(subdomains) == 0 {
		return
	}

	fmt.Println()
	PrintSectionDivider()
	fmt.Printf("\n%s %s\n", Blue("→"), Bold("FINAL INTELLIGENCE SUMMARY"))
	PrintSectionDivider()
	fmt.Println()

	for _, intel := range subdomains {
		printSubdomainIntelligence(intel)
	}
}

// SubdomainIntel contains all intelligence for a subdomain
type SubdomainIntel struct {
	Subdomain       string
	StatusCode      int
	ResponseTime    string
	IPs             []string
	Location        string
	ASN             string
	ASNDesc         string
	HTTPTitle       string
	HTTPSize        string
	TechStack       []string
	SecurityPresent []string
	SecurityMissing []string
	WAF             string
	TLS             string
	OpenPorts       []int
	Cloud           string
	TLSAltNames     []string
	AdminEndpoints  []EndpointDetail
	APIEndpoints    []EndpointDetail
	Files           []string
	Vulnerabilities []VulnDetail
	CVEs            []CVEDetail
}

// EndpointDetail contains endpoint information
type EndpointDetail struct {
	Path   string
	Status string
}

// VulnDetail contains vulnerability details
type VulnDetail struct {
	Type      string
	Severity  string
	Endpoint  string
	Parameter string
	Details   string
}

// CVEDetail contains CVE details
type CVEDetail struct {
	ID          string
	Severity    string
	Score       float64
	Service     string
	Status      string // "VERIFIED" or "EXPLOITABLE"
	Details     string
}

func printSubdomainIntelligence(intel SubdomainIntel) {
	// Status code color
	statusColor := Green
	if intel.StatusCode >= 400 {
		statusColor = Red
	} else if intel.StatusCode >= 300 {
		statusColor = Yellow
	}

	// Main subdomain header
	fmt.Printf("%s %s [%s] %s\n",
		Yellow("○"),
		Blue(intel.Subdomain),
		statusColor(fmt.Sprintf("%d", intel.StatusCode)),
		White(intel.ResponseTime))

	// IP addresses
	if len(intel.IPs) > 0 {
		ipList := formatIPListShort(intel.IPs, 3)
		fmt.Printf("    IP: %s\n", Yellow(ipList))
	}

	// Location and ASN
	if intel.Location != "" && intel.ASN != "" {
		fmt.Printf("    Location: %s | %s %s\n",
			Green(intel.Location),
			Yellow(fmt.Sprintf("AS%s", intel.ASN)),
			Green(intel.ASNDesc))
	}

	// HTTP details
	if intel.HTTPTitle != "" {
		fmt.Printf("    HTTP: \"%s\" (%s)\n", Green(intel.HTTPTitle), White(intel.HTTPSize))
	}

	// Technology stack
	if len(intel.TechStack) > 0 {
		techList := formatListShort(intel.TechStack, 5)
		fmt.Printf("    Tech: %s\n", Green(techList))
	}

	// Security headers
	if intel.WAF != "" || intel.TLS != "" || len(intel.SecurityPresent) > 0 {
		secParts := []string{}
		if intel.WAF != "" {
			secParts = append(secParts, fmt.Sprintf("WAF: %s", intel.WAF))
		}
		if intel.TLS != "" {
			secParts = append(secParts, fmt.Sprintf("TLS: %s", intel.TLS))
		}
		fmt.Printf("    Security: %s\n", Green(strings.Join(secParts, " | ")))
	}

	// Open ports
	if len(intel.OpenPorts) > 0 {
		portList := formatPortListShort(intel.OpenPorts, 8)
		fmt.Printf("    Ports: %s\n", Yellow(portList))
	}

	// Headers present/missing
	if len(intel.SecurityPresent) > 0 || len(intel.SecurityMissing) > 0 {
		parts := []string{}
		if len(intel.SecurityPresent) > 0 {
			parts = append(parts, formatListShort(intel.SecurityPresent, 3))
		}
		if len(intel.SecurityMissing) > 0 {
			parts = append(parts, fmt.Sprintf("Missing: %s", formatListShort(intel.SecurityMissing, 3)))
		}
		fmt.Printf("    Headers: %s\n", Yellow(strings.Join(parts, " | ")))
	}

	// Cloud provider
	if intel.Cloud != "" {
		fmt.Printf("    Cloud: %s\n", Green(intel.Cloud))
	}

	// TLS alternative names
	if len(intel.TLSAltNames) > 0 {
		altList := formatListShort(intel.TLSAltNames, 3)
		fmt.Printf("    TLS Alt: %s\n", Yellow(altList))
	}

	// Discovered endpoints
	if len(intel.AdminEndpoints) > 0 || len(intel.APIEndpoints) > 0 {
		foundParts := []string{}
		if len(intel.AdminEndpoints) > 0 {
			adminList := formatEndpointListShort(intel.AdminEndpoints, 5)
			foundParts = append(foundParts, fmt.Sprintf("Admin: %s", adminList))
		}
		if len(intel.APIEndpoints) > 0 {
			apiList := formatEndpointListShort(intel.APIEndpoints, 5)
			foundParts = append(foundParts, fmt.Sprintf("API: %s", apiList))
		}
		fmt.Printf("    FOUND: %s\n", Green(strings.Join(foundParts, " | ")))
	}

	// Files
	if len(intel.Files) > 0 {
		fileList := formatListShort(intel.Files, 5)
		fmt.Printf("    Files: %s\n", Yellow(fileList))
	}

	// Vulnerabilities section
	if len(intel.Vulnerabilities) > 0 {
		fmt.Printf("    %s\n", Red(Bold("VULNERABILITIES:")))
		for _, vuln := range intel.Vulnerabilities {
			sevColor := Red
			if vuln.Severity == "MEDIUM" {
				sevColor = Yellow
			} else if vuln.Severity == "LOW" {
				sevColor = White
			}

			if vuln.Parameter != "" {
				fmt.Printf("       - [%s] %s at %s (param: %s)\n",
					sevColor(vuln.Severity),
					Yellow(vuln.Type),
					Blue(vuln.Endpoint),
					White(vuln.Parameter))
			} else {
				fmt.Printf("       - [%s] %s at %s\n",
					sevColor(vuln.Severity),
					Yellow(vuln.Type),
					Blue(vuln.Endpoint))
			}
			if vuln.Details != "" {
				fmt.Printf("         %s\n", White(vuln.Details))
			}
		}
	}

	// CVE section (verified only)
	if len(intel.CVEs) > 0 {
		fmt.Printf("    %s\n", Red(Bold("CVE (Verified):")))
		for _, cve := range intel.CVEs {
			sevColor := Red
			if cve.Severity == "HIGH" {
				sevColor = Yellow
			} else if cve.Severity == "MEDIUM" {
				sevColor = Yellow
			}

			statusLabel := cve.Status
			statusColor := Green
			if cve.Status == "EXPLOITABLE" {
				statusColor = Red
			}

			fmt.Printf("       - %s: %s (%s/%.1f) [%s]\n",
				Blue(cve.Service),
				Yellow(cve.ID),
				sevColor(cve.Severity),
				cve.Score,
				statusColor(statusLabel))

			if cve.Details != "" {
				fmt.Printf("         %s\n", White(cve.Details))
			}
		}
	}

	fmt.Println()
}

// Helper formatting functions
func formatIPListShort(ips []string, max int) string {
	if len(ips) <= max {
		return strings.Join(ips, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(ips[:max], ", "), len(ips)-max)
}

func formatListShort(items []string, max int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(items[:max], ", "), len(items)-max)
}

func formatPortListShort(ports []int, max int) string {
	if len(ports) == 0 {
		return "None"
	}

	var portStrs []string
	for _, port := range ports {
		portStrs = append(portStrs, fmt.Sprintf("%d", port))
	}

	if len(portStrs) <= max {
		return strings.Join(portStrs, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(portStrs[:max], ", "), len(portStrs)-max)
}

func formatEndpointListShort(endpoints []EndpointDetail, max int) string {
	if len(endpoints) == 0 {
		return ""
	}

	var parts []string
	limit := max
	if len(endpoints) < limit {
		limit = len(endpoints)
	}

	for i := 0; i < limit; i++ {
		parts = append(parts, fmt.Sprintf("%s (%s)", endpoints[i].Path, endpoints[i].Status))
	}

	result := strings.Join(parts, ", ")
	if len(endpoints) > max {
		result += fmt.Sprintf(" +%d more", len(endpoints)-max)
	}

	return result
}

// PrintFinalStatistics prints the final summary statistics
func PrintFinalStatistics(totalSubdomains, totalVulns, criticalVulns, highVulns, totalCVEs, exploitableCVEs int) {
	fmt.Println()
	PrintSectionDivider()
	fmt.Printf("\n%s %s\n", Blue("→"), Bold("SCAN STATISTICS"))
	PrintSectionDivider()
	fmt.Println()

	fmt.Printf("   Total Subdomains Analyzed: %s\n", Green(fmt.Sprintf("%d", totalSubdomains)))
	fmt.Printf("   Total Vulnerabilities Found: %s\n", Yellow(fmt.Sprintf("%d", totalVulns)))
	fmt.Printf("   Critical Vulnerabilities: %s\n", Red(fmt.Sprintf("%d", criticalVulns)))
	fmt.Printf("   High Vulnerabilities: %s\n", Yellow(fmt.Sprintf("%d", highVulns)))
	fmt.Printf("   Total Verified CVEs: %s\n", Yellow(fmt.Sprintf("%d", totalCVEs)))
	fmt.Printf("   Exploitable CVEs: %s\n", Red(fmt.Sprintf("%d", exploitableCVEs)))

	fmt.Println()
}
// PrintHostHeader prints a host header with separator
func PrintHostHeader(ip, os string) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 63))
	fmt.Println()
	fmt.Printf("%s %s\n", Bold("HOST:"), Green(ip))
	if os != "" {
		fmt.Printf("%s %s\n", Bold("OS Detected:"), Blue(os))
	} else {
		fmt.Printf("%s %s\n", Bold("OS Detected:"), Yellow("Unknown"))
	}
	fmt.Println()
}

// PrintOpenPort prints an open port with service info
func PrintOpenPort(port int, protocol, service, version, product string) {
	serviceStr := strings.ToUpper(service)
	if serviceStr == "" {
		serviceStr = "UNKNOWN"
	}

	versionStr := ""
	if product != "" && version != "" {
		versionStr = fmt.Sprintf("%s %s", product, version)
	} else if product != "" {
		versionStr = product
	} else if version != "" {
		versionStr = version
	}

	fmt.Printf("%s [%d/%s] %s\n", Bold("OPEN PORTS:"), port, protocol, Green(serviceStr))
	if versionStr != "" {
		fmt.Printf("   └─ Service: %s\n", Blue(versionStr))
	}
}

// PrintServiceAnalysisInline prints AI analysis inline with port info
func PrintServiceAnalysisInline(detectedVersion string, isOutdated bool, latestVersion string, vulns []string, exploitability string) {
	// Show detected version
	if detectedVersion != "" {
		fmt.Printf("   ├─ Detected Version: %s\n", Blue(detectedVersion))
	}

	// Show latest version if available
	if latestVersion != "" {
		fmt.Printf("   ├─ Latest Version: %s\n", Cyan(latestVersion))
	}

	// Version status with colored dot
	statusDot := Green("●") // Green dot for up-to-date
	statusText := "UP-TO-DATE"
	if isOutdated {
		statusDot = Red("●") // Red dot for outdated
		statusText = "OUTDATED"
	} else if latestVersion == "" {
		statusDot = Yellow("●") // Yellow dot for unknown
		statusText = "UNKNOWN"
	}
	fmt.Printf("   ├─ %s Status: %s\n", statusDot, statusText)

	// Vulnerabilities - Show ALL verified CVEs (no truncation)
	if len(vulns) > 0 {
		fmt.Printf("   ├─ CVEs: %s\n", Bold(Red(fmt.Sprintf("%d found", len(vulns)))))
		// Show ALL CVEs (no limit)
		for i := 0; i < len(vulns); i++ {
			fmt.Printf("   │  %s %s\n", Red("├─"), Yellow(vulns[i]))
		}
	} else {
		fmt.Printf("   ├─ CVEs: %s\n", Green("None found"))
	}

	// Exploitability with colored indicator
	exploitDot := Green("●")
	exploitColor := Green
	switch exploitability {
	case "CRITICAL":
		exploitDot = Red("●")
		exploitColor = Red
	case "HIGH":
		exploitDot = Red("●")
		exploitColor = Red
	case "MODERATE":
		exploitDot = Yellow("●")
		exploitColor = Yellow
	case "LOW":
		exploitDot = Yellow("●")
		exploitColor = Yellow
	case "NONE":
		exploitDot = Green("●")
		exploitColor = Green
	default:
		exploitDot = Gray("●")
		exploitColor = Gray
	}
	fmt.Printf("   └─ %s Exploitability: %s\n", exploitDot, exploitColor(Bold(exploitability)))
	fmt.Println()
}

// PrintAIAnalysisStart prints the AI analysis start message
func PrintAIAnalysisStart(model string) {
	fmt.Println()
	fmt.Println(strings.Repeat("─", 63))
	fmt.Println()
	fmt.Printf("%s AI Service Analysis (%s)...\n", Blue("→"), Yellow(model))
	fmt.Println()
}

// PrintServiceAnalysis prints AI analysis for a single service
func PrintServiceAnalysis(ip string, port int, service, version string, isOutdated bool, latestVersion string, vulns []string, exploitability string) {
	// Service header
	serviceStr := service
	if version != "" {
		serviceStr = fmt.Sprintf("%s %s", service, version)
	}
	fmt.Printf("[%s:%d] %s\n", Green(ip), port, Bold(serviceStr))

	// Version status with colored dot
	statusDot := Green("●") // Green dot for up-to-date
	statusText := "UP-TO-DATE"
	if isOutdated {
		statusDot = Red("●") // Red dot for outdated
		statusText = fmt.Sprintf("OUTDATED (Latest: %s)", latestVersion)
	} else if latestVersion == "" {
		statusDot = Yellow("●") // Yellow dot for unknown
		statusText = "UNKNOWN"
	}
	fmt.Printf("   ├─ %s Version Status: %s\n", statusDot, statusText)

	// Vulnerabilities - Show ALL verified CVEs (no truncation)
	fmt.Printf("   ├─ Vulnerabilities: %s\n", Bold(fmt.Sprintf("%d found", len(vulns))))
	if len(vulns) > 0 {
		// Show ALL CVEs (no limit)
		for i := 0; i < len(vulns); i++ {
			if i == len(vulns)-1 {
				fmt.Printf("   │  %s %s\n", Red("└─"), Yellow(vulns[i]))
			} else {
				fmt.Printf("   │  %s %s\n", Red("├─"), Yellow(vulns[i]))
			}
		}
	}

	// Exploitability with colored indicator
	exploitDot := Green("●")
	switch exploitability {
	case "CRITICAL":
		exploitDot = Red("●")
	case "HIGH":
		exploitDot = Red("●")
	case "MODERATE":
		exploitDot = Yellow("●")
	case "LOW":
		exploitDot = Yellow("●")
	case "NONE":
		exploitDot = Green("●")
	default:
		exploitDot = Yellow("●")
	}
	fmt.Printf("   └─ %s Exploitable: %s\n", exploitDot, Bold(exploitability))
	fmt.Println()
}

// PrintAIAnalysisSummary prints the final summary of AI analysis
func PrintAIAnalysisSummary(hostsAnalyzed, servicesAnalyzed, totalVulns int, duration time.Duration) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 63))
	fmt.Println()
	fmt.Printf("%s Port Scanning & AI Analysis completed (%.1fs)\n", Green("✓"), duration.Seconds())
	fmt.Printf("  └─ %d hosts analyzed, %d services, %d vulnerabilities found\n",
		hostsAnalyzed, servicesAnalyzed, totalVulns)
	fmt.Println()
}

// PrintAINotAvailable prints when AI is not available
func PrintAINotAvailable(reason string) {
	fmt.Println()
	fmt.Printf("%s AI Analysis skipped: %s\n", Red("✗"), reason)
	fmt.Printf("%s Ollama server must be running for AI analysis\n", Yellow("ℹ"))
	fmt.Printf("%s Start Ollama with: %s\n", Yellow("ℹ"), Bold("ollama serve"))
	fmt.Printf("%s Pull model with: %s\n", Yellow("ℹ"), Bold("ollama pull deepseek-r1:8b"))
	fmt.Println()
}

// PrintSecurityFindingAnalysis prints AI analysis of a security finding
func PrintSecurityFindingAnalysis(findingType, subdomain, riskLevel, exploitability string, cves []string, attackChain, poc string) {
	// Risk level with colored dot
	var riskDot string
	var riskColor func(a ...interface{}) string
	switch riskLevel {
	case "CRITICAL":
		riskDot = Red("●")
		riskColor = Red
	case "HIGH":
		riskDot = Red("●")
		riskColor = Red
	case "MODERATE":
		riskDot = Yellow("●")
		riskColor = Yellow
	case "LOW":
		riskDot = Green("●")
		riskColor = Green
	default:
		riskDot = Gray("●")
		riskColor = Gray
	}

	fmt.Println()
	fmt.Printf("%s AI Analysis: %s\n", Blue("→"), Yellow(findingType))
	fmt.Printf("   ├─ %s Risk: %s\n", riskDot, riskColor(Bold(riskLevel)))

	if exploitability != "" {
		fmt.Printf("   ├─ Exploitability: %s\n", Yellow(exploitability))
	}

	// Show CVEs if available
	if len(cves) > 0 {
		fmt.Printf("   ├─ CVEs: %s\n", Red(strings.Join(cves, ", ")))
	}

	// Deep mode features
	if attackChain != "" {
		fmt.Printf("   ├─ Attack Chain: %s\n", Cyan(attackChain))
	}

	if poc != "" {
		fmt.Printf("   └─ PoC: %s\n", Cyan(poc))
	} else if attackChain == "" && len(cves) == 0 {
		fmt.Printf("   └─ No additional details\n")
	}
	fmt.Println()
}

// PrintSecurityAnalysisSummary prints summary of AI security analysis
func PrintSecurityAnalysisSummary(totalFindings, criticalCount, highCount, moderateCount, lowCount int, duration string) {
	fmt.Println()
	fmt.Printf("%s Security Analysis Summary\n", Bold("→"))
	fmt.Printf("   ├─ Total Findings Analyzed: %s\n", Cyan(fmt.Sprintf("%d", totalFindings)))
	fmt.Printf("   ├─ Critical Risk: %s\n", Red(fmt.Sprintf("%d", criticalCount)))
	fmt.Printf("   ├─ High Risk: %s\n", Red(fmt.Sprintf("%d", highCount)))
	fmt.Printf("   ├─ Moderate Risk: %s\n", Yellow(fmt.Sprintf("%d", moderateCount)))
	fmt.Printf("   ├─ Low Risk: %s\n", Green(fmt.Sprintf("%d", lowCount)))
	fmt.Printf("   └─ Analysis Duration: %s\n", duration)
	fmt.Println()
}

// PrintSubdomainHeader prints subdomain with status code
// SubdomainInfo holds detailed subdomain information
type SubdomainInfo struct {
	Subdomain string
	StatusCode int
	IP         string
	CNAME      string
	Location   string  // City, Country
	PTR        string
	MX         []string
	TLSAltNames []string
	TechStack  []string
}

func PrintSubdomainHeader(subdomain string, statusCode int) {
	fmt.Println()
	var statusColor func(string) string
	var dotColor func(string) string

	if statusCode == 0 {
		// Connection failed/timeout
		statusColor = func(s string) string { return Gray(s) }
		dotColor = func(s string) string { return Gray(s) }
	} else if statusCode >= 500 {
		// Server error
		statusColor = func(s string) string { return Red(s) }
		dotColor = func(s string) string { return Red(s) }
	} else if statusCode >= 400 {
		// Client error
		statusColor = func(s string) string { return Red(s) }
		dotColor = func(s string) string { return Red(s) }
	} else if statusCode >= 300 {
		// Redirect
		statusColor = func(s string) string { return Yellow(s) }
		dotColor = func(s string) string { return Yellow(s) }
	} else if statusCode >= 200 {
		// Success
		statusColor = func(s string) string { return Green(s) }
		dotColor = func(s string) string { return Green(s) }
	} else {
		// Unknown
		statusColor = func(s string) string { return Gray(s) }
		dotColor = func(s string) string { return Gray(s) }
	}

	fmt.Printf("%s %s %s\n", dotColor("●"), Bold(subdomain), statusColor(fmt.Sprintf("[%d]", statusCode)))
	fmt.Println()
}

// PrintSubdomainHeaderDetailed prints subdomain with detailed information
func PrintSubdomainHeaderDetailed(info SubdomainInfo) {
	fmt.Println()
	var statusColor func(string) string
	var dotColor func(string) string

	if info.StatusCode == 0 {
		// Connection failed/timeout
		statusColor = func(s string) string { return Gray(s) }
		dotColor = func(s string) string { return Gray(s) }
	} else if info.StatusCode >= 500 {
		// Server error
		statusColor = func(s string) string { return Red(s) }
		dotColor = func(s string) string { return Red(s) }
	} else if info.StatusCode >= 400 {
		// Client error
		statusColor = func(s string) string { return Red(s) }
		dotColor = func(s string) string { return Red(s) }
	} else if info.StatusCode >= 300 {
		// Redirect
		statusColor = func(s string) string { return Yellow(s) }
		dotColor = func(s string) string { return Yellow(s) }
	} else if info.StatusCode >= 200 {
		// Success
		statusColor = func(s string) string { return Green(s) }
		dotColor = func(s string) string { return Green(s) }
	} else {
		// Unknown
		statusColor = func(s string) string { return Gray(s) }
		dotColor = func(s string) string { return Gray(s) }
	}

	// Main header: subdomain + status code
	fmt.Printf("%s %s %s\n", dotColor("●"), Bold(info.Subdomain), statusColor(fmt.Sprintf("[%d]", info.StatusCode)))

	// Show detailed info on next lines
	if info.IP != "" {
		fmt.Printf("   ├─ IP: %s\n", Cyan(info.IP))
	}

	if info.CNAME != "" {
		fmt.Printf("   ├─ CNAME: %s\n", Yellow(info.CNAME))
	}

	if info.Location != "" {
		fmt.Printf("   ├─ Location: %s\n", Blue(info.Location))
	}

	if info.PTR != "" {
		fmt.Printf("   ├─ PTR: %s\n", Magenta(info.PTR))
	}

	if len(info.MX) > 0 {
		fmt.Printf("   ├─ MX: %s\n", Yellow(strings.Join(info.MX, ", ")))
	}

	if len(info.TLSAltNames) > 0 {
		// Show first 3 alt names
		altNames := info.TLSAltNames
		if len(altNames) > 3 {
			altNames = altNames[:3]
			fmt.Printf("   ├─ TLS Alt Names: %s (+%d more)\n", Green(strings.Join(altNames, ", ")), len(info.TLSAltNames)-3)
		} else {
			fmt.Printf("   ├─ TLS Alt Names: %s\n", Green(strings.Join(altNames, ", ")))
		}
	}

	if len(info.TechStack) > 0 {
		fmt.Printf("   └─ Tech: %s\n", Cyan(strings.Join(info.TechStack, ", ")))
	}

	fmt.Println()
}

// PrintSecurityHeadersResult prints security headers analysis result
func PrintSecurityHeadersResult(grade string, missingHeaders []string, risk string) {
	fmt.Printf("%s Security Headers Analysis\n", Blue("→"))
	if grade != "" {
		fmt.Printf("   ├─ Grade: %s\n", Bold(grade))
	}
	if len(missingHeaders) > 0 {
		fmt.Printf("   ├─ Missing: %s\n", Yellow(strings.Join(missingHeaders, ", ")))
	}

	riskDot := Green("●")
	riskColor := Green
	switch risk {
	case "CRITICAL":
		riskDot = Red("●")
		riskColor = Red
	case "HIGH":
		riskDot = Red("●")
		riskColor = Red
	case "MEDIUM":
		riskDot = Yellow("●")
		riskColor = Yellow
	case "LOW":
		riskDot = Green("●")
		riskColor = Green
	}
	fmt.Printf("   └─ %s Risk: %s\n", riskDot, riskColor(Bold(risk)))
	fmt.Println()
}

// PrintTLSResult prints TLS/SSL analysis result
func PrintTLSResult(version string, vulnerabilities []string, risk string) {
	fmt.Printf("%s TLS/SSL Configuration\n", Blue("→"))

	// Always show TLS version if available
	if version != "" {
		fmt.Printf("   ├─ Version: %s\n", Cyan(version))
	}

	if len(vulnerabilities) == 0 {
		fmt.Printf("   └─ %s No vulnerabilities found\n", Green("✓"))
	} else {
		for i, vuln := range vulnerabilities {
			if i == len(vulnerabilities)-1 {
				fmt.Printf("   ├─ Vulnerability: %s\n", Yellow(vuln))
				riskDot := Yellow("●")
				riskColor := Yellow
				if risk == "CRITICAL" || risk == "HIGH" {
					riskDot = Red("●")
					riskColor = Red
				}
				fmt.Printf("   └─ %s Risk: %s\n", riskDot, riskColor(Bold(risk)))
			} else {
				fmt.Printf("   ├─ Vulnerability: %s\n", Yellow(vuln))
			}
		}
	}
	fmt.Println()
}

// PrintTakeoverResult prints subdomain takeover check result
func PrintTakeoverResult(vulnerable bool, service, evidence, risk string) {
	fmt.Printf("%s Subdomain Takeover Check\n", Blue("→"))
	if !vulnerable {
		fmt.Printf("   └─ %s Not vulnerable\n", Green("✓"))
	} else {
		fmt.Printf("   ├─ Service: %s\n", Yellow(service))
		fmt.Printf("   ├─ Evidence: %s\n", evidence)
		riskDot := Red("●")
		riskColor := Red
		if risk == "MEDIUM" || risk == "LOW" {
			riskDot = Yellow("●")
			riskColor = Yellow
		}
		fmt.Printf("   └─ %s Risk: %s\n", riskDot, riskColor(Bold(risk)))
	}
	fmt.Println()
}

// PrintCloudAssetResult prints cloud asset discovery result
func PrintCloudAssetResult(assetType, url, status string, isWritable bool, risk string) {
	fmt.Printf("%s Cloud Assets Discovery\n", Blue("→"))
	if assetType == "" {
		fmt.Printf("   └─ %s No cloud assets found\n", Green("✓"))
	} else {
		fmt.Printf("   ├─ Type: %s\n", Yellow(assetType))
		fmt.Printf("   ├─ URL: %s\n", Cyan(url))
		fmt.Printf("   ├─ Status: %s\n", status)
		if isWritable {
			fmt.Printf("   ├─ %s WRITABLE!\n", Red("⚠"))
		}
		riskDot := Green("●")
		riskColor := Green
		switch risk {
		case "CRITICAL":
			riskDot = Red("●")
			riskColor = Red
		case "HIGH":
			riskDot = Red("●")
			riskColor = Red
		case "MEDIUM":
			riskDot = Yellow("●")
			riskColor = Yellow
		}
		fmt.Printf("   └─ %s Risk: %s\n", riskDot, riskColor(Bold(risk)))
	}
	fmt.Println()
}

// PrintCORSResult prints CORS configuration result
func PrintCORSResult(issues []string, risk string) {
	fmt.Printf("%s CORS Configuration\n", Blue("→"))
	if len(issues) == 0 {
		fmt.Printf("   └─ %s No misconfigurations\n", Green("✓"))
	} else {
		for i, issue := range issues {
			if i == len(issues)-1 {
				fmt.Printf("   ├─ Issue: %s\n", Yellow(issue))
				riskDot := Yellow("●")
				riskColor := Yellow
				if risk == "CRITICAL" || risk == "HIGH" {
					riskDot = Red("●")
					riskColor = Red
				}
				fmt.Printf("   └─ %s Risk: %s\n", riskDot, riskColor(Bold(risk)))
			} else {
				fmt.Printf("   ├─ Issue: %s\n", Yellow(issue))
			}
		}
	}
	fmt.Println()
}

// PrintSecretsResult prints JavaScript secrets scan result
func PrintSecretsResult(secretType, foundIn, key, risk string) {
	fmt.Printf("%s JavaScript Secrets Scan\n", Blue("→"))
	if secretType == "" {
		fmt.Printf("   └─ %s No secrets found\n", Green("✓"))
	} else {
		fmt.Printf("   ├─ Type: %s\n", Yellow(secretType))
		fmt.Printf("   ├─ Found in: %s\n", Cyan(foundIn))
		fmt.Printf("   ├─ Key: %s\n", Gray(key))
		riskDot := Green("●")
		riskColor := Green
		switch risk {
		case "CRITICAL":
			riskDot = Red("●")
			riskColor = Red
		case "HIGH":
			riskDot = Red("●")
			riskColor = Red
		case "MEDIUM":
			riskDot = Yellow("●")
			riskColor = Yellow
		}
		fmt.Printf("   └─ %s Risk: %s\n", riskDot, riskColor(Bold(risk)))
	}
	fmt.Println()
}

// PrintFinalSecuritySummary prints final summary
func PrintFinalSecuritySummary(totalSubdomains, criticalCount, highCount, mediumCount, lowCount int) {
	fmt.Println()
	fmt.Printf("%s Security Analysis Summary\n", Bold("→"))
	fmt.Printf("   ├─ Total Subdomains Analyzed: %s\n", Cyan(fmt.Sprintf("%d", totalSubdomains)))
	fmt.Printf("   ├─ Critical Findings: %s\n", Red(fmt.Sprintf("%d", criticalCount)))
	fmt.Printf("   ├─ High Findings: %s\n", Red(fmt.Sprintf("%d", highCount)))
	fmt.Printf("   ├─ Medium Findings: %s\n", Yellow(fmt.Sprintf("%d", mediumCount)))
	fmt.Printf("   └─ Low Findings: %s\n", Green(fmt.Sprintf("%d", lowCount)))
	fmt.Println()
}
