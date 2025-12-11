package terminal

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Colors
var (
	Blue   = color.New(color.FgCyan).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
	Green  = color.New(color.FgGreen).SprintFunc()
	Red    = color.New(color.FgRed).SprintFunc()
	White  = color.New(color.FgWhite).SprintFunc()
	Bold   = color.New(color.Bold).SprintFunc()
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

// PrintToolStarting prints when a tool starts
func PrintToolStarting(toolName string, message ...string) {
	if len(message) > 0 {
		fmt.Printf("%s %s is running (%s)\n", Blue("●"), toolName, message[0])
	} else {
		fmt.Printf("%s %s is running", Blue("●"), toolName)
	}
}

// PrintToolRunning updates the tool status (yellow dot with animation)
func PrintToolRunning(toolName string, elapsed time.Duration) {
	// Move cursor to beginning of line and clear it
	fmt.Printf("\r\033[K")
	
	// Animated dots based on elapsed time
	dots := strings.Repeat(".", int(elapsed.Seconds())%4)
	fmt.Printf("%s %s is running%s", Yellow("●"), toolName, dots)
}

// PrintToolCompleted prints when a tool completes successfully
func PrintToolCompleted(toolName string, count int, duration time.Duration) {
	// Clear line and print success
	fmt.Printf("\r\033[K")
	fmt.Printf("%s %s enumeration complete [%d found] (%.1fs)\n", 
		Green("●"), toolName, count, duration.Seconds())
}

// PrintToolFailed prints when a tool fails
func PrintToolFailed(toolName string, err error, duration time.Duration) {
	// Clear line and print error
	fmt.Printf("\r\033[K")
	fmt.Printf("%s %s failed: %v (%.1fs)\n", 
		Red("●"), toolName, err, duration.Seconds())
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
func PrintURLDiscoverySummary(katanaURLs, gauURLs, totalURLs int) {
	fmt.Println()
	fmt.Println(Bold("URL Discovery Summary:"))
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

// PrintASNSummary prints the ASN distribution summary
func PrintASNSummary(totalASNs int, topASNs []string) {
	if totalASNs == 0 {
		return
	}

	fmt.Println()
	fmt.Println(Bold("ASN Distribution:"))

	// Show top ASNs
	for i, asn := range topASNs {
		if i >= 5 { // Show only top 5
			break
		}
		if i == len(topASNs)-1 {
			fmt.Printf("   └── %s\n", Green(asn))
		} else {
			fmt.Printf("   ├── %s\n", Green(asn))
		}
	}

	if len(topASNs) > 5 {
		fmt.Printf("   └── ...and %s more\n", Yellow(fmt.Sprintf("%d", len(topASNs)-5)))
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
