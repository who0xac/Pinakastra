package scanner

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/who0xac/pinakastra/pkg/api"
	"github.com/who0xac/pinakastra/pkg/asn"
	"github.com/who0xac/pinakastra/pkg/cloud"
	"github.com/who0xac/pinakastra/pkg/config"
	"github.com/who0xac/pinakastra/pkg/cors"
	"github.com/who0xac/pinakastra/pkg/exploit"
	"github.com/who0xac/pinakastra/pkg/fingerprint"
	"github.com/who0xac/pinakastra/pkg/httpprobe"
	"github.com/who0xac/pinakastra/pkg/intelligence"
	"github.com/who0xac/pinakastra/pkg/ipresolve"
	"github.com/who0xac/pinakastra/pkg/output/formatter"
	"github.com/who0xac/pinakastra/pkg/output/terminal"
	"github.com/who0xac/pinakastra/pkg/port"
	"github.com/who0xac/pinakastra/pkg/secrets"
	"github.com/who0xac/pinakastra/pkg/security"
	"github.com/who0xac/pinakastra/pkg/subdomain"
	"github.com/who0xac/pinakastra/pkg/takeover"
	"github.com/who0xac/pinakastra/pkg/tls"
	"github.com/who0xac/pinakastra/pkg/urldiscovery"
	"github.com/who0xac/pinakastra/pkg/utils"

	"github.com/fatih/color"
)

// ScanConfig holds the configuration for a scan
type ScanConfig struct {
	Domain        string
	OutputDir     string
	OutputFile    string
	OutputFormats string
	Mode          string
	EnableAI      bool
	Threads       int
	RateLimit     int
	UseTor        bool
	NoBruteforce  bool
	NoPortscan    bool
	Ports         string
}

// Scanner handles the full scanning workflow
type Scanner struct {
	Config           *ScanConfig
	ctx              context.Context
	cancel           context.CancelFunc
	termCapture      *utils.TerminalCapture
	scanResult       *formatter.ScanResult
	startTime        time.Time
	interruptCount   int32          // Atomic counter for Ctrl+C presses
	lastInterruptTime time.Time      // Time of last interrupt
	skipPhase        chan struct{}  // Channel to signal phase skip
}

// Color helpers
var (
	Bold  = color.New(color.Bold).SprintFunc()
	Green = color.New(color.FgGreen).SprintFunc()
)

// NewScanner creates a new scanner instance
func NewScanner(config *ScanConfig) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())

	scanner := &Scanner{
		Config:           config,
		ctx:              ctx,
		cancel:           cancel,
		termCapture:      utils.NewTerminalCapture(),
		startTime:        time.Now(),
		interruptCount:   0,
		lastInterruptTime: time.Time{},
		skipPhase:        make(chan struct{}, 1),
	}

	// Set up signal handling for Ctrl+C
	scanner.setupSignalHandler()

	return scanner
}

// setupSignalHandler configures signal handling for graceful interruption
func (s *Scanner) setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		for range sigChan {
			now := time.Now()
			atomic.AddInt32(&s.interruptCount, 1)

			// Check if this is a double Ctrl+C (within 2 seconds)
			if !s.lastInterruptTime.IsZero() && now.Sub(s.lastInterruptTime) < 2*time.Second {
				// Double Ctrl+C - exit immediately
				fmt.Printf("\n\n%s %s\n", terminal.Red(">>"), terminal.Bold(terminal.Red("Double Ctrl+C detected - Exiting immediately...")))
				s.cancel()
				os.Exit(1)
			}

			s.lastInterruptTime = now

			// Single Ctrl+C - skip current step
			fmt.Printf("\n\n%s %s\n", terminal.Yellow(">>"), terminal.Bold(terminal.Yellow("Ctrl+C detected - Skipping current step...")))
			fmt.Printf("   %s\n", terminal.Gray("(Press Ctrl+C again within 2 seconds to exit completely)"))

			// Signal phase skip
			select {
			case s.skipPhase <- struct{}{}:
			default:
				// Channel already has a skip signal
			}

			// Reset counter after 2 seconds
			time.AfterFunc(2*time.Second, func() {
				atomic.StoreInt32(&s.interruptCount, 0)
			})
		}
	}()
}

// shouldSkipPhase checks if current phase should be skipped due to Ctrl+C
// This function consumes the skip signal, so it should only be called once per phase
func (s *Scanner) shouldSkipPhase() bool {
	select {
	case <-s.skipPhase:
		// Skip signal received
		fmt.Println("   >> Skipping...")
		return true
	default:
		return false
	}
}

// Run executes the full scanning workflow
func (s *Scanner) Run() error {
	// Create output directory with timestamp
	timestamp := time.Now().Format("2006-01-02_150405")
	scanID := fmt.Sprintf("%s_%s", s.Config.Domain, timestamp)
	outputPath := filepath.Join(s.Config.OutputDir, scanID)

	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	s.log(fmt.Sprintf("Output directory: %s", outputPath))
	terminal.PrintProgress(fmt.Sprintf("Output directory: %s", outputPath))
	fmt.Println()

	// Initialize scan result
	s.scanResult = &formatter.ScanResult{
		Metadata: formatter.ScanMetadata{
			Domain:    s.Config.Domain,
			ScanID:    scanID,
			StartTime: s.startTime,
			Mode:      s.Config.Mode,
			EnableAI:  s.Config.EnableAI,
			UseTor:    s.Config.UseTor,
			Version:   "1.0.0",
		},
		Subdomains: formatter.SubdomainResults{
			ToolResults: make(map[string]int),
		},
		TerminalOutput: []string{},
	}

	// Declare variables at function scope
	var subdomains []string
	var err error

	// Phase 1: Subdomain Enumeration
	if s.shouldSkipPhase() {
		subdomains = []string{}
	} else {
		subdomains, err = s.runSubdomainEnumeration(outputPath)
		if err != nil {
			return fmt.Errorf("subdomain enumeration failed: %v", err)
		}
	}

	// Phase 2: HTTP Probing
	if !s.shouldSkipPhase() {
		_, err = s.runHTTPProbing(outputPath, subdomains)
		if err != nil {
			return fmt.Errorf("HTTP probing failed: %v", err)
		}
	}

	// Phase 3: IP Resolution
	if !s.shouldSkipPhase() {
		_, err = s.runIPResolution(outputPath)
		if err != nil {
			return fmt.Errorf("IP resolution failed: %v", err)
		}
	}

	// Phase 4: Web Security Analysis (NO AI required - always runs)
	if !s.shouldSkipPhase() {
		if err := s.runWebSecurityAnalysis(outputPath, subdomains); err != nil {
			s.log(fmt.Sprintf("Web security analysis warning: %v", err))
		}
	}

	// Phase 5: URL Discovery (runs regardless of AI setting)
	if !s.shouldSkipPhase() {
		_, err = s.runURLDiscovery(outputPath)
		if err != nil {
			return fmt.Errorf("URL discovery failed: %v", err)
		}
	}

	// Exit early if AI is disabled (Port scanning requires AI)
	if !s.Config.EnableAI {
		// Finalize metadata and generate outputs before exiting
		s.scanResult.Metadata.EndTime = time.Now()
		s.scanResult.Metadata.Duration = s.scanResult.Metadata.EndTime.Sub(s.startTime).String()
		s.scanResult.TerminalOutput = s.termCapture.GetLines()

		if err := s.generateOutputs(outputPath); err != nil {
			return fmt.Errorf("failed to generate outputs: %v", err)
		}

		fmt.Println()
		terminal.PrintSectionDivider()
		terminal.PrintSuccess(fmt.Sprintf("Scan completed! Results saved to: %s", outputPath))
		terminal.PrintInfo("Web Security Analysis completed (100% verified data)")
		terminal.PrintInfo("AI is disabled. Skipped: Port Scanning and AI Analysis")
		terminal.PrintInfo("Enable with --enable-ai for AI-powered port scanning and deep analysis")

		terminal.PrintSectionDivider()
		fmt.Println()
		return nil
	}

	// Phase 6: Port Scanning (requires AI, optional, skip if --no-portscan)
	if !s.Config.NoPortscan && !s.shouldSkipPhase() {
		if err := s.runPortScan(outputPath); err != nil {
			s.log(fmt.Sprintf("Port scan warning: %v", err))
		}
	}

	// Phase 7: Active Exploitation (requires AI)
	if s.Config.EnableAI && !s.shouldSkipPhase() {
		if err := s.runActiveExploitation(outputPath); err != nil {
			s.log(fmt.Sprintf("Active exploitation warning: %v", err))
		}
	}

	// Finalize metadata
	s.scanResult.Metadata.EndTime = time.Now()
	s.scanResult.Metadata.Duration = s.scanResult.Metadata.EndTime.Sub(s.startTime).String()
	s.scanResult.TerminalOutput = s.termCapture.GetLines()

	// Generate output files
	if err := s.generateOutputs(outputPath); err != nil {
		return fmt.Errorf("failed to generate outputs: %v", err)
	}

	msg := fmt.Sprintf("Scan completed! Results saved to: %s", outputPath)
	s.log(msg)
	terminal.PrintSuccess(msg)

	// Shutdown Ollama server if it was used (AI was enabled)
	if s.Config.EnableAI {
		s.shutdownOllama()
	}

	return nil
}

// runSubdomainEnumeration runs Phase 1: Subdomain Discovery
func (s *Scanner) runSubdomainEnumeration(outputPath string) ([]string, error) {
	phaseStart := time.Now()

	enumerator := subdomain.NewPassiveEnumerator(s.Config.Domain, outputPath)

	// Load configuration file for API keys
	cfg, err := config.LoadConfig()
	if err != nil {
		s.log(fmt.Sprintf("Warning: Could not load config: %v", err))
	}

	// Configure optional paths from config directory
	if resolversPath, err := config.GetResolversPath(); err == nil {
		enumerator.Resolvers = resolversPath
	}
	if wordlistPath, err := config.GetWordlistPath(); err == nil {
		enumerator.Wordlist = wordlistPath
	}

	// Load API keys from config if available
	if cfg != nil {
		if cfg.APIKeys.Chaos != "" {
			enumerator.ChaosAPIKey = cfg.APIKeys.Chaos
		}
		if cfg.APIKeys.Shodan != "" {
			enumerator.ShodanAPIKey = cfg.APIKeys.Shodan
		}
	}

	// Skip brute force if requested
	if s.Config.NoBruteforce {
		enumerator.SkipPuredns = true
	}

	// Run enumeration
	subdomains, err := enumerator.Run(s.ctx)
	if err != nil {
		return nil, err
	}

	// Save final results
	subdomainsFile := filepath.Join(outputPath, "all_subdomains.txt")
	if err := writeLinesToFile(subdomainsFile, subdomains); err != nil {
		return nil, fmt.Errorf("failed to save subdomains: %v", err)
	}

	// Extract and save API endpoints
	apis := subdomain.ExtractAPIs(subdomains)
	if len(apis) > 0 {
		apisFile := filepath.Join(outputPath, "api_endpoints.txt")
		if err := writeLinesToFile(apisFile, apis); err != nil {
			return nil, fmt.Errorf("failed to save API endpoints: %v", err)
		}
		s.log(fmt.Sprintf("Extracted %d potential API endpoints", len(apis)))
		terminal.PrintSuccess(fmt.Sprintf("Extracted %d potential API endpoints", len(apis)))
	}

	// Update scan result
	s.scanResult.Subdomains.Subdomains = subdomains
	s.scanResult.Subdomains.UniqueCount = len(subdomains)
	s.scanResult.Subdomains.APICount = len(apis)
	s.scanResult.Subdomains.APIs = apis
	s.scanResult.Subdomains.Duration = time.Since(phaseStart).String()

	return subdomains, nil
}

// runHTTPProbing runs Phase 2: HTTP Probing
func (s *Scanner) runHTTPProbing(outputPath string, subdomains []string) ([]string, error) {
	phaseStart := time.Now()

	// Save subdomains to temp file for httpx
	subdomainsFile := filepath.Join(outputPath, "all_subdomains.txt")

	prober := httpprobe.NewHTTPProber(subdomainsFile, outputPath)

	// Configure proxy if TOR is enabled
	if s.Config.UseTor {
		prober.Proxy = "socks5://127.0.0.1:9050"
	}

	// Configure threads and rate limit
	prober.Threads = 150
	prober.RateLimit = 50

	// Run HTTP probing
	result, err := prober.Run(s.ctx)
	if err != nil {
		return nil, err
	}

	// Update scan result
	s.scanResult.HTTPProbe.TotalProbed = result.TotalProbed
	s.scanResult.HTTPProbe.LiveCount = result.LiveCount
	s.scanResult.HTTPProbe.Duration = time.Since(phaseStart).String()

	// Convert live URLs to formatter.LiveURL
	liveURLs := make([]formatter.LiveURL, len(result.LiveURLs))
	for i, url := range result.LiveURLs {
		liveURLs[i] = formatter.LiveURL{
			URL: url,
		}
	}
	s.scanResult.HTTPProbe.LiveURLs = liveURLs


	return result.LiveURLs, nil
}

// runIPResolution runs Phase 3: IP Resolution
func (s *Scanner) runIPResolution(outputPath string) (map[string][]string, error) {
	phaseStart := time.Now()

	terminal.PrintSectionHeader("IP RESOLUTION")
	fmt.Println()

	liveURLsFile := filepath.Join(outputPath, "live_urls.txt")

	resolver := ipresolve.NewIPResolver(liveURLsFile, outputPath)

	// Run IP resolution
	result, err := resolver.Run(s.ctx)
	if err != nil {
		return nil, err
	}

	// Perform ASN lookups
	ipsOnlyFile := filepath.Join(outputPath, "ips_only.txt")
	ips, err := readLinesFromFile(ipsOnlyFile)
	if err != nil || len(ips) == 0 {
		terminal.PrintProgress(fmt.Sprintf("Skipping ASN lookup (no IPs found: %v)", err))
	} else {
		terminal.PrintPhaseStarting("Fetching ASN information")

		asnLookup := asn.NewLookup()
		asnResults, err := asnLookup.LookupBatch(s.ctx, ips)
		if err == nil && len(asnResults) > 0 {
			// Get statistics
			stats := asn.GetStatistics(asnResults)

			// Build detailed display info
			var displayInfos []terminal.ASNDisplayInfo
			for _, stat := range stats {
				// Get country from first IP in this ASN
				country := ""
				for _, asnInfo := range asnResults {
					if asnInfo.ASN == stat.ASN {
						country = asnInfo.Country
						break
					}
				}

				displayInfos = append(displayInfos, terminal.ASNDisplayInfo{
					ASN:         stat.ASN,
					Description: stat.Description,
					Country:     country,
					IPCount:     stat.Count,
					SampleIPs:   stat.IPs,
				})
			}

			// Print detailed ASN summary
			terminal.PrintASNSummaryDetailed(displayInfos, len(ips))

			// Save ASN data to file
			asnFile := filepath.Join(outputPath, "asn_data.txt")
			s.saveASNData(asnFile, stats)

			s.log(fmt.Sprintf("ASN lookup completed: %d unique ASNs found", len(stats)))
		} else {
			terminal.PrintProgress("No ASN information found")
		}
	}


	// Print completion summary
	fmt.Println()
	terminal.PrintSectionDivider()
	duration := time.Since(phaseStart)
	terminal.PrintSuccess(fmt.Sprintf("IP Resolution completed in %s", duration.Round(time.Second)))
	terminal.PrintInfo(fmt.Sprintf("Resolved %d unique IPs", len(result.ResolvedIPs)))
	fmt.Println()


	return result.ResolvedIPs, nil
}

// saveASNData saves ASN statistics to a file
func (s *Scanner) saveASNData(filename string, stats []*asn.ASNStats) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, stat := range stats {
		fmt.Fprintf(file, "AS%s | %s | %d IPs\n", stat.ASN, stat.Description, stat.Count)
		for _, ip := range stat.IPs {
			fmt.Fprintf(file, "  - %s\n", ip)
		}
		fmt.Fprintln(file)
	}

	return nil
}

// runURLDiscovery runs Phase 5: URL Discovery
func (s *Scanner) runURLDiscovery(outputPath string) ([]string, error) {
	phaseStart := time.Now()

	liveURLsFile := filepath.Join(outputPath, "live_urls.txt")

	terminal.PrintSectionHeader("URL DISCOVERY")

	// Run Katana
	katanaRunner := urldiscovery.NewKatanaRunner(liveURLsFile, outputPath)
	_, err := katanaRunner.Run(s.ctx)
	if err != nil {
		s.log(fmt.Sprintf("Katana failed: %v", err))
	}

	// Run GAU
	gauRunner := urldiscovery.NewGAURunner(liveURLsFile, outputPath)
	_, err = gauRunner.Run(s.ctx)
	if err != nil {
		s.log(fmt.Sprintf("GAU failed: %v", err))
	}

	// Merge and deduplicate
	merger := urldiscovery.NewURLMerger(outputPath)
	mergeResult, err := merger.Merge()
	if err != nil {
		return nil, err
	}

	s.log(fmt.Sprintf("URL Discovery completed: %d unique URLs found", mergeResult.TotalURLs))

	// Read all URLs
	allURLsFile := filepath.Join(outputPath, "all_urls.txt")
	urls, err := readLinesFromFile(allURLsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read URLs: %v", err)
	}

	_ = phaseStart


	return urls, nil
}

// subdomainAnalysisResult holds all analysis results for a subdomain
type subdomainAnalysisResult struct {
	subdomain        string
	info             terminal.SubdomainInfo
	findings         int
	criticalCount    int
	highCount        int
	moderateCount    int
	lowCount         int
	output           []string // Buffered output lines
}

// testResult holds individual test results
type testResult struct {
	name          string
	output        string
	findings      int
	criticalCount int
	highCount     int
	moderateCount int
	lowCount      int
}

// runWebSecurityAnalysis runs Phase 4: Web Security Analysis (NO AI) with parallel processing
func (s *Scanner) runWebSecurityAnalysis(outputPath string, subdomains []string) error {
	phaseStart := time.Now()

	terminal.PrintSectionHeader("WEB SECURITY ANALYSIS")
	fmt.Println()

	// Deduplicate subdomains (www.example.com and example.com are same)
	uniqueSubdomains := s.deduplicateSubdomains(subdomains)

	// Create buffered channels for parallel processing
	numWorkers := 5 // Process 5 subdomains concurrently
	jobs := make(chan string, len(uniqueSubdomains))
	results := make(chan *subdomainAnalysisResult, len(uniqueSubdomains))

	// Start worker pool
	for w := 0; w < numWorkers; w++ {
		go s.analyzeSubdomainWorker(jobs, results)
	}

	// Send jobs
	for _, subdomain := range uniqueSubdomains {
		jobs <- subdomain
	}
	close(jobs)

	// Print results IMMEDIATELY as they finish (real-time display)
	totalFindings := 0
	var criticalCount, highCount, moderateCount, lowCount int

	for i := 0; i < len(uniqueSubdomains); i++ {
		result := <-results

		// Print output immediately as each subdomain finishes
		for _, line := range result.output {
			fmt.Print(line)
		}

		// Update totals
		totalFindings += result.findings
		criticalCount += result.criticalCount
		highCount += result.highCount
		moderateCount += result.moderateCount
		lowCount += result.lowCount
	}

	// Print final summary
	fmt.Println()
	terminal.PrintSectionDivider()
	terminal.PrintFinalSecuritySummary(totalFindings, criticalCount, highCount, moderateCount, lowCount)
	terminal.PrintSuccess(fmt.Sprintf("Web Security Analysis completed in %s", time.Since(phaseStart)))
	terminal.PrintSectionDivider()
	fmt.Println()

	return nil
}

// analyzeSubdomainWorker processes a single subdomain with all tests in parallel
func (s *Scanner) analyzeSubdomainWorker(jobs <-chan string, results chan<- *subdomainAnalysisResult) {
	for subdomain := range jobs {
		result := &subdomainAnalysisResult{
			subdomain: subdomain,
			output:    make([]string, 0),
		}

		// Gather detailed subdomain information
		result.info = s.getSubdomainInfo(subdomain)

		// Buffer to capture all output for this subdomain
		var buf strings.Builder

		// Add visual separator for better readability
		buf.WriteString(terminal.Gray("   ─────────────────────────────────────────────────────────────────────────────\n"))
		buf.WriteString("\n")

		// Print subdomain header to buffer
		buf.WriteString(fmt.Sprintf("   %s %s %s\n",
			s.getColoredDot(result.info.StatusCode),
			terminal.Bold(result.info.Subdomain),
			s.getColoredStatusCode(result.info.StatusCode)))

		if result.info.IP != "" {
			buf.WriteString(fmt.Sprintf("      ├─ IP: %s\n", terminal.Cyan(result.info.IP)))
		}
		if result.info.CNAME != "" {
			buf.WriteString(fmt.Sprintf("      ├─ CNAME: %s\n", terminal.Yellow(result.info.CNAME)))
		}
		if result.info.Location != "" {
			buf.WriteString(fmt.Sprintf("      ├─ Location: %s\n", terminal.Blue(result.info.Location)))
		}
		if result.info.PTR != "" {
			buf.WriteString(fmt.Sprintf("      └─ PTR: %s\n", terminal.Magenta(result.info.PTR)))
		}
		buf.WriteString("\n")

		// Run all 6 tests in parallel using goroutines
		testResults := make(chan testResult, 6)

		// 1. Security Headers Analysis (parallel)
		go func() {
			tr := testResult{name: "Security Headers"}
			var testBuf strings.Builder

			testBuf.WriteString(fmt.Sprintf("      %s Security Headers Analysis is running...\n", terminal.Blue("→")))
			securityResults := s.runSecurityHeadersAnalysis([]string{subdomain})
			foundIssue := false

			if analysis, exists := securityResults[subdomain]; exists {
				if len(analysis.MissingHeaders) > 0 || analysis.Grade != "" {
					risk := s.calculateHeadersRisk(analysis.Grade)
					testBuf.WriteString(s.formatSecurityHeadersResult(analysis.Grade, analysis.MissingHeaders, risk))
					tr.findings++
					foundIssue = true
					s.updateRiskCounts(&tr, risk)
				}
			}

			if !foundIssue {
				testBuf.WriteString(fmt.Sprintf("         %s No issues found\n", terminal.Green("✓")))
			}

			tr.output = testBuf.String()
			testResults <- tr
		}()

		// 2. TLS/SSL Analysis (parallel)
		go func() {
			tr := testResult{name: "TLS/SSL"}
			var testBuf strings.Builder

			testBuf.WriteString(fmt.Sprintf("      %s TLS/SSL Analysis is running...\n", terminal.Blue("→")))
			tlsResults := s.runTLSAnalysis([]string{subdomain})
			foundIssue := false

			if analysis, exists := tlsResults[subdomain]; exists {
				if len(analysis.Vulnerabilities) > 0 {
					risk := s.calculateTLSRisk(analysis.Vulnerabilities)
					testBuf.WriteString(s.formatTLSResult(analysis.Version, analysis.Vulnerabilities, risk))
					tr.findings++
					foundIssue = true
					s.updateRiskCounts(&tr, risk)
				} else if analysis.Version != "" {
					testBuf.WriteString(s.formatTLSResult(analysis.Version, []string{}, ""))
				}
			}

			if !foundIssue {
				testBuf.WriteString(fmt.Sprintf("         %s No issues found\n", terminal.Green("✓")))
			}

			tr.output = testBuf.String()
			testResults <- tr
		}()

		// 3. Subdomain Takeover (parallel)
		go func() {
			tr := testResult{name: "Takeover"}
			var testBuf strings.Builder

			testBuf.WriteString(fmt.Sprintf("      %s Subdomain Takeover Detection is running...\n", terminal.Blue("→")))
			takeoverVulns := s.runTakeoverDetection([]string{subdomain})
			foundIssue := false

			if len(takeoverVulns) > 0 {
				vuln := takeoverVulns[0]
				risk := "MEDIUM"
				if strings.ToUpper(vuln.Severity) == "CRITICAL" {
					risk = "CRITICAL"
				} else if strings.ToUpper(vuln.Severity) == "HIGH" {
					risk = "HIGH"
				}
				testBuf.WriteString(s.formatTakeoverResult(vuln.Service, vuln.Evidence, risk))
				tr.findings++
				foundIssue = true
				s.updateRiskCounts(&tr, risk)
			}

			if !foundIssue {
				testBuf.WriteString(fmt.Sprintf("         %s No issues found\n", terminal.Green("✓")))
			}

			tr.output = testBuf.String()
			testResults <- tr
		}()

		// 4. Cloud Assets (parallel)
		go func() {
			tr := testResult{name: "Cloud"}
			var testBuf strings.Builder

			testBuf.WriteString(fmt.Sprintf("      %s Cloud Assets Discovery is running...\n", terminal.Blue("→")))
			cloudAssets := s.runCloudDiscovery()
			foundIssue := false

			for _, asset := range cloudAssets {
				if s.extractSubdomainFromURL(asset.URL) == subdomain {
					risk := "LOW"
					if asset.IsWritable {
						risk = "CRITICAL"
					} else if asset.Status == "public" {
						risk = "MEDIUM"
					}
					testBuf.WriteString(s.formatCloudAssetResult(asset.Provider, asset.URL, asset.Status, asset.IsWritable, risk))
					tr.findings++
					foundIssue = true
					s.updateRiskCounts(&tr, risk)
				}
			}

			if !foundIssue {
				testBuf.WriteString(fmt.Sprintf("         %s No issues found\n", terminal.Green("✓")))
			}

			tr.output = testBuf.String()
			testResults <- tr
		}()

		// 5. CORS Detection (parallel)
		go func() {
			tr := testResult{name: "CORS"}
			var testBuf strings.Builder

			testBuf.WriteString(fmt.Sprintf("      %s CORS Misconfiguration Detection is running...\n", terminal.Blue("→")))
			corsResults := s.runCORSDetection([]string{subdomain})
			foundIssue := false

			if issues, exists := corsResults[subdomain]; exists {
				if len(issues) > 0 {
					issueDescriptions := make([]string, 0, len(issues))
					maxRisk := "LOW"
					for _, issue := range issues {
						issueDescriptions = append(issueDescriptions, issue.Description)
						severity := strings.ToUpper(issue.Severity)
						if severity == "CRITICAL" {
							maxRisk = "CRITICAL"
						} else if severity == "HIGH" && maxRisk != "CRITICAL" {
							maxRisk = "HIGH"
						} else if severity == "MEDIUM" && maxRisk != "HIGH" && maxRisk != "CRITICAL" {
							maxRisk = "MEDIUM"
						}
					}
					testBuf.WriteString(s.formatCORSResult(issueDescriptions, maxRisk))
					tr.findings++
					foundIssue = true
					s.updateRiskCounts(&tr, maxRisk)
				}
			}

			if !foundIssue {
				testBuf.WriteString(fmt.Sprintf("         %s No issues found\n", terminal.Green("✓")))
			}

			tr.output = testBuf.String()
			testResults <- tr
		}()

		// 6. Secrets Scanning (parallel)
		go func() {
			tr := testResult{name: "Secrets"}
			var testBuf strings.Builder

			testBuf.WriteString(fmt.Sprintf("      %s JavaScript Secrets Scanning is running...\n", terminal.Blue("→")))
			secretResults := s.runSecretsScanning([]string{subdomain})
			foundIssue := false

			for url, secretFindings := range secretResults {
				if s.extractSubdomainFromURL(url) == subdomain {
					for _, secret := range secretFindings {
						risk := strings.ToUpper(secret.Severity)
						testBuf.WriteString(s.formatSecretsResult(secret.Type, secret.Source, secret.Match, risk))
						tr.findings++
						foundIssue = true
						s.updateRiskCounts(&tr, risk)
					}
				}
			}

			if !foundIssue {
				testBuf.WriteString(fmt.Sprintf("         %s No issues found\n", terminal.Green("✓")))
			}

			tr.output = testBuf.String()
			testResults <- tr
		}()

		// Collect all test results in order
		testOrder := []string{"Security Headers", "TLS/SSL", "Takeover", "Cloud", "CORS", "Secrets"}
		testResultMap := make(map[string]testResult)

		for i := 0; i < 6; i++ {
			tr := <-testResults
			testResultMap[tr.name] = tr
		}

		// Append test outputs in the correct order
		for _, testName := range testOrder {
			tr := testResultMap[testName]
			buf.WriteString(tr.output)
			result.findings += tr.findings
			result.criticalCount += tr.criticalCount
			result.highCount += tr.highCount
			result.moderateCount += tr.moderateCount
			result.lowCount += tr.lowCount
		}

		buf.WriteString("\n")
		result.output = append(result.output, buf.String())

		// Send result
		results <- result
	}
}

// Helper functions for formatting (to avoid direct terminal printing in workers)
func (s *Scanner) getColoredDot(statusCode int) string {
	if statusCode == 0 {
		return terminal.Gray("●")
	} else if statusCode >= 500 {
		return terminal.Red("●")
	} else if statusCode >= 400 {
		return terminal.Red("●")
	} else if statusCode >= 300 {
		return terminal.Yellow("●")
	} else if statusCode >= 200 {
		return terminal.Green("●")
	}
	return terminal.Gray("●")
}

func (s *Scanner) getColoredStatusCode(statusCode int) string {
	var color func(string) string
	if statusCode == 0 {
		color = func(s string) string { return terminal.Gray(s) }
	} else if statusCode >= 500 {
		color = func(s string) string { return terminal.Red(s) }
	} else if statusCode >= 400 {
		color = func(s string) string { return terminal.Red(s) }
	} else if statusCode >= 300 {
		color = func(s string) string { return terminal.Yellow(s) }
	} else if statusCode >= 200 {
		color = func(s string) string { return terminal.Green(s) }
	} else {
		color = func(s string) string { return terminal.Gray(s) }
	}
	return color(fmt.Sprintf("[%d]", statusCode))
}

func (s *Scanner) updateRiskCounts(tr *testResult, risk string) {
	switch risk {
	case "CRITICAL":
		tr.criticalCount++
	case "HIGH":
		tr.highCount++
	case "MEDIUM":
		tr.moderateCount++
	case "LOW":
		tr.lowCount++
	}
}

func (s *Scanner) formatSecurityHeadersResult(grade string, missingHeaders []string, risk string) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("      %s Security Headers Analysis\n", terminal.Blue("→")))
	buf.WriteString(fmt.Sprintf("         ├─ Grade: %s\n", terminal.Yellow(grade)))
	buf.WriteString(fmt.Sprintf("         ├─ Missing: %s\n", terminal.White(strings.Join(missingHeaders, ", "))))

	riskColor := terminal.Yellow
	if risk == "CRITICAL" {
		riskColor = terminal.Red
	} else if risk == "HIGH" {
		riskColor = terminal.Red
	}
	buf.WriteString(fmt.Sprintf("         └─ %s Risk: %s\n\n", terminal.Red("●"), riskColor(risk)))
	return buf.String()
}

func (s *Scanner) formatTLSResult(version string, vulnerabilities []string, risk string) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("      %s TLS/SSL Configuration\n", terminal.Blue("→")))
	buf.WriteString(fmt.Sprintf("         ├─ Version: %s\n", terminal.Green(version)))

	if len(vulnerabilities) > 0 {
		buf.WriteString(fmt.Sprintf("         ├─ Vulnerabilities: %s\n", terminal.Red(strings.Join(vulnerabilities, ", "))))
		riskColor := terminal.Yellow
		if risk == "CRITICAL" || risk == "HIGH" {
			riskColor = terminal.Red
		}
		buf.WriteString(fmt.Sprintf("         └─ %s Risk: %s\n\n", terminal.Red("●"), riskColor(risk)))
	} else {
		buf.WriteString(fmt.Sprintf("         └─ %s No vulnerabilities found\n\n", terminal.Green("✓")))
	}
	return buf.String()
}

func (s *Scanner) formatTakeoverResult(service, evidence, risk string) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("      %s Subdomain Takeover Detected!\n", terminal.Blue("→")))
	buf.WriteString(fmt.Sprintf("         ├─ Service: %s\n", terminal.Yellow(service)))
	buf.WriteString(fmt.Sprintf("         ├─ Evidence: %s\n", terminal.White(evidence)))

	riskColor := terminal.Yellow
	if risk == "CRITICAL" || risk == "HIGH" {
		riskColor = terminal.Red
	}
	buf.WriteString(fmt.Sprintf("   └─ %s Risk: %s\n\n", terminal.Red("●"), riskColor(risk)))
	return buf.String()
}

func (s *Scanner) formatCloudAssetResult(provider, url, status string, isWritable bool, risk string) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("      %s Cloud Asset Found\n", terminal.Blue("→")))
	buf.WriteString(fmt.Sprintf("         ├─ Provider: %s\n", terminal.Cyan(provider)))
	buf.WriteString(fmt.Sprintf("         ├─ URL: %s\n", terminal.White(url)))
	buf.WriteString(fmt.Sprintf("         ├─ Status: %s\n", terminal.Yellow(status)))

	if isWritable {
		buf.WriteString(fmt.Sprintf("         ├─ Writable: %s\n", terminal.Red("YES")))
	}

	riskColor := terminal.Yellow
	if risk == "CRITICAL" || risk == "HIGH" {
		riskColor = terminal.Red
	}
	buf.WriteString(fmt.Sprintf("   └─ %s Risk: %s\n\n", terminal.Red("●"), riskColor(risk)))
	return buf.String()
}

func (s *Scanner) formatCORSResult(issues []string, risk string) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("      %s CORS Configuration\n", terminal.Blue("→")))

	for _, issue := range issues {
		buf.WriteString(fmt.Sprintf("         ├─ Issue: %s\n", terminal.White(issue)))
	}

	riskColor := terminal.Yellow
	if risk == "CRITICAL" || risk == "HIGH" {
		riskColor = terminal.Red
	}
	buf.WriteString(fmt.Sprintf("   └─ %s Risk: %s\n\n", terminal.Red("●"), riskColor(risk)))
	return buf.String()
}

func (s *Scanner) formatSecretsResult(secretType, source, match, risk string) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("      %s Secret Found in JavaScript\n", terminal.Blue("→")))
	buf.WriteString(fmt.Sprintf("         ├─ Type: %s\n", terminal.Yellow(secretType)))
	buf.WriteString(fmt.Sprintf("         ├─ Source: %s\n", terminal.Cyan(source)))
	buf.WriteString(fmt.Sprintf("         ├─ Match: %s\n", terminal.White(match)))

	riskColor := terminal.Yellow
	if risk == "CRITICAL" || risk == "HIGH" {
		riskColor = terminal.Red
	}
	buf.WriteString(fmt.Sprintf("   └─ %s Risk: %s\n\n", terminal.Red("●"), riskColor(risk)))
	return buf.String()
}

// runPortScan runs Phase 6: Port Scanning with AI Analysis
func (s *Scanner) runPortScan(outputPath string) error {
	terminal.PrintSectionHeader("PORT SCANNING")
	fmt.Println()

	// Check if Ollama is running and model is available
	s.ensureOllamaRunning()

	phaseStart := time.Now()
	ipsFile := filepath.Join(outputPath, "ips_only.txt")

	// Verify IPs file exists
	if _, err := os.Stat(ipsFile); os.IsNotExist(err) {
		s.log("Skipping port scan: no IPs file found")
		terminal.PrintWarning("No resolved IPs found - skipping port scan")
		return nil
	}

	// Run Nmap scan (top 10 critical ports only)
	terminal.PrintInfo("Running Nmap scan on top 10 critical ports...")
	scanner := port.NewScanner(ipsFile, outputPath)
	result, err := scanner.Run(s.ctx)
	if err != nil {
		return err
	}

	if result.TotalHosts == 0 {
		s.log("Port scan completed: no results")
		terminal.PrintWarning("No open ports found")
		fmt.Println()
		return nil
	}

	fmt.Println()
	terminal.PrintInfo(fmt.Sprintf("Found %d hosts with open ports", result.TotalHosts))
	terminal.PrintInfo("Starting AI-powered service analysis...")
	fmt.Println()

	// Print host information with OS detection and open ports
	// AI Analysis (if enabled)
	totalVulns := 0
	if s.Config.EnableAI {
		aiModel := "deepseek-r1:7b"
		totalVulns = s.runAIServiceAnalysis(result.Hosts, outputPath, aiModel)
	} else {
		// Just print ports without AI analysis
		for _, host := range result.Hosts {
			terminal.PrintHostHeader(host.IP, host.OS)

			// Print open ports for this host
			for _, svc := range host.Services {
				terminal.PrintOpenPort(svc.Port, svc.Protocol, svc.Service, svc.Version, svc.Product)
			}
		}
	}

	// Print final summary
	fmt.Println()
	terminal.PrintSectionDivider()
	terminal.PrintAIAnalysisSummary(
		result.TotalHosts,
		result.OpenPorts,
		totalVulns,
		time.Since(phaseStart),
	)
	fmt.Println()

	s.log(fmt.Sprintf("Port scan completed: %d open ports, %d vulnerabilities found",
		result.OpenPorts, totalVulns))


	return nil
}

// runActiveExploitation runs Phase 7: Active Exploitation with AI
func (s *Scanner) runActiveExploitation(outputPath string) error {
	terminal.PrintSectionHeader("ACTIVE EXPLOITATION")

	phaseStart := time.Now()

	// Load URLs from all_urls.txt (created by URL merger)
	urlsFile := filepath.Join(outputPath, "all_urls.txt")
	if _, err := os.Stat(urlsFile); os.IsNotExist(err) {
		terminal.PrintWarning("No URLs found - skipping active exploitation")
		s.log("Active exploitation skipped: no URLs file found")
		return nil
	}

	// Read and parse URLs
	data, err := os.ReadFile(urlsFile)
	if err != nil {
		return fmt.Errorf("failed to read URLs file: %v", err)
	}

	// Parse URLs by subdomain
	urlsBySubdomain := make(map[string][]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse URL to extract subdomain
		parsedURL, err := url.Parse(line)
		if err != nil {
			continue
		}

		subdomain := parsedURL.Host
		urlsBySubdomain[subdomain] = append(urlsBySubdomain[subdomain], line)
	}

	if len(urlsBySubdomain) == 0 {
		terminal.PrintWarning("No valid URLs found - skipping active exploitation")
		s.log("Active exploitation skipped: no valid URLs")
		return nil
	}

	// Check if Ollama is running, start if needed
	s.ensureOllamaRunning()

	// Initialize exploit scanner with faster timeout and smaller model for 8GB RAM
	exploitScanner := exploit.NewScanner(
		7, // timeout in seconds (reduced for faster scanning)
		"deepseek-r1:7b", // 7b model uses 6-7GB RAM (vs 8b which needs 8-10GB)
		"http://localhost:11434",
	)

	// Create exploits output directory
	exploitsDir := filepath.Join(outputPath, "exploits")
	if err := os.MkdirAll(exploitsDir, 0755); err != nil {
		return fmt.Errorf("failed to create exploits directory: %v", err)
	}

	// Prepare subdomain list
	subdomainList := make([]string, 0, len(urlsBySubdomain))
	for subdomain := range urlsBySubdomain {
		subdomainList = append(subdomainList, subdomain)
	}

	// Track statistics
	allExploits := make([]exploit.Exploit, 0)
	totalSubdomains := len(subdomainList)

	fmt.Printf("\n%s Testing %d subdomains for vulnerabilities...\n\n", terminal.Blue("→"), totalSubdomains)

	// Process each subdomain sequentially to show progress
	for idx, subdomain := range subdomainList {
		urls := urlsBySubdomain[subdomain]

		// Print subdomain header with progress
		fmt.Printf("   ─────────────────────────────────────────────────────────────────────────────\n\n")
		fmt.Printf("   %s %s [%d/%d] - %d URLs\n\n", terminal.Yellow("●"), terminal.Bold(subdomain), idx+1, totalSubdomains, len(urls))

		// Create progress channel and displayer
		progressChan := make(chan string, 8)
		displayer := NewProgressDisplayer()
		displayer.InitializeTests()

		// Start progress display goroutine
		go func() {
			for msg := range progressChan {
				displayer.UpdateProgress(msg)
			}
			displayer.Finalize()
		}()

		// Run actual scan (tests run in parallel internally)
		result, err := exploitScanner.ScanSubdomainWithProgress(s.ctx, subdomain, urls, progressChan)
		close(progressChan)

		if err != nil {
			fmt.Printf("      %s Error: %v\n\n", terminal.Red("✗"), err)
			continue
		}

		// Small delay to ensure all progress messages are printed
		time.Sleep(100 * time.Millisecond)
		fmt.Println()

		// Display results
		if result != nil && len(result.Exploits) > 0 {
			fmt.Printf("\n      %s Found %d vulnerabilities:\n\n", terminal.Red("⚠"), len(result.Exploits))

			for _, expl := range result.Exploits {
				// Color based on severity
				severityColor := terminal.Yellow
				if expl.Severity == "critical" || expl.Severity == "high" {
					severityColor = terminal.Red
				} else if expl.Severity == "low" || expl.Severity == "info" {
					severityColor = terminal.Green
				}

				fmt.Printf("         %s %s\n", terminal.Red("●"), severityColor(strings.ToUpper(expl.Severity)))
				fmt.Printf("            ├─ Type: %s\n", terminal.Yellow(string(expl.VulnType)))
				fmt.Printf("            ├─ URL: %s\n", terminal.Cyan(expl.URL))
				if expl.Payload != "" {
					fmt.Printf("            ├─ Payload: %s\n", terminal.White(expl.Payload))
				}
				if expl.Impact != "" {
					fmt.Printf("            └─ %s\n", terminal.Gray(expl.Impact))
				}
				fmt.Println()
			}

			allExploits = append(allExploits, result.Exploits...)
		} else {
			fmt.Printf("\n      %s No vulnerabilities found\n\n", terminal.Green("✓"))
		}
	}

	fmt.Printf("   ─────────────────────────────────────────────────────────────────────────────\n\n")

	// Generate exploit files
	if len(allExploits) > 0 {
		if err := exploit.GenerateExploitFiles(allExploits, exploitsDir); err != nil {
			s.log(fmt.Sprintf("Failed to generate exploit files: %v", err))
		}
	}

	// Print summary
	fmt.Printf("%s %s\n", terminal.Green("✓"), terminal.Bold("Active Exploitation Summary"))
	fmt.Printf("   ├─ Subdomains Tested: %s\n", terminal.Cyan(fmt.Sprintf("%d", totalSubdomains)))
	fmt.Printf("   ├─ Vulnerabilities Found: %s\n", terminal.Red(fmt.Sprintf("%d", len(allExploits))))
	fmt.Printf("   └─ Duration: %s\n", terminal.Gray(time.Since(phaseStart).String()))

	if len(allExploits) > 0 {
		fmt.Printf("\n%s Exploit reports saved to: %s\n", terminal.Blue("ℹ"), terminal.Cyan(exploitsDir))
	}


	return nil
}

// runAIServiceAnalysis performs AI analysis on discovered services
func (s *Scanner) runAIServiceAnalysis(hosts []port.HostInfo, outputPath, model string) int {
	analyzer := intelligence.NewServiceAnalyzer(model)

	// Check if Ollama is available
	if !analyzer.IsAvailable(s.ctx) {
		terminal.PrintAINotAvailable("Ollama service not running")
		s.log("AI Analysis skipped: Ollama not available")
		return 0
	}

	// Check if model is available
	modelAvailable, err := analyzer.CheckModel(s.ctx)
	if err != nil || !modelAvailable {
		terminal.PrintAINotAvailable(fmt.Sprintf("Model %s not found", model))
		s.log(fmt.Sprintf("AI Analysis skipped: Model %s not available", model))
		return 0
	}

	terminal.PrintAIAnalysisStart(model)

	// Create output file
	analysisFile := filepath.Join(outputPath, "network_scan_ai_analysis.txt")
	f, err := os.Create(analysisFile)
	if err != nil {
		s.log(fmt.Sprintf("Failed to create AI analysis file: %v", err))
		return 0
	}
	defer f.Close()

	// Write header
	fmt.Fprintf(f, "=== NETWORK SCAN AI ANALYSIS ===\n")
	fmt.Fprintf(f, "Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "Model: %s\n\n", model)

	totalVulns := 0

	// Analyze each host
	for _, host := range hosts {
		// Print host header to terminal and file
		if len(host.Services) > 0 {
			terminal.PrintHostHeader(host.IP, host.OS)

			// Write host header to file
			fmt.Fprintf(f, "%s\n", strings.Repeat("═", 63))
			fmt.Fprintf(f, "\nHOST: %s\n", host.IP)
			if host.OS != "" {
				fmt.Fprintf(f, "OS: %s\n", host.OS)
			}
			fmt.Fprintf(f, "\nOPEN PORTS & SERVICES:\n")

			// List all services in file
			for _, svc := range host.Services {
				serviceStr := svc.Service
				if svc.Product != "" && svc.Version != "" {
					serviceStr = fmt.Sprintf("%s %s", svc.Product, svc.Version)
				} else if svc.Product != "" {
					serviceStr = svc.Product
				}
				fmt.Fprintf(f, "  - %d/%s   → %-10s → %s\n", svc.Port, svc.Protocol, strings.ToUpper(svc.Service), serviceStr)
			}

			fmt.Fprintf(f, "\n%s\n\n", strings.Repeat("─", 63))
			fmt.Fprintf(f, "SERVICE ANALYSIS:\n\n")
		}

		// Analyze each service and print immediately
		for _, svc := range host.Services {
			// Skip if no service name
			if svc.Service == "" {
				continue
			}

			// Print port info first
			terminal.PrintOpenPort(svc.Port, svc.Protocol, svc.Service, svc.Version, svc.Product)

			// Call AI for analysis
			analysis, err := analyzer.AnalyzeService(s.ctx, svc.IP, svc.Port, svc.Service, svc.Version, svc.Product)
			if err != nil {
				s.log(fmt.Sprintf("AI analysis failed for %s:%d - %v", svc.IP, svc.Port, err))
				// Don't show error to user - just skip this service
				continue
			}

			totalVulns += len(analysis.Vulnerabilities)

			// Build detected version string
			detectedVersion := ""
			if svc.Product != "" && svc.Version != "" {
				detectedVersion = fmt.Sprintf("%s %s", svc.Product, svc.Version)
			} else if svc.Product != "" {
				detectedVersion = svc.Product
			} else if svc.Version != "" {
				detectedVersion = svc.Version
			}

			// Print AI analysis immediately after port info
			terminal.PrintServiceAnalysisInline(
				detectedVersion,
				analysis.IsOutdated,
				analysis.LatestVersion,
				analysis.Vulnerabilities,
				analysis.Exploitability,
			)

			// Write to file
			serviceStr := analysis.Service
			if analysis.Version != "" {
				serviceStr = fmt.Sprintf("%s %s", analysis.Service, analysis.Version)
			}
			fmt.Fprintf(f, "[%s:%d] %s\n", analysis.IP, analysis.Port, serviceStr)

			// Version status
			if analysis.IsOutdated {
				fmt.Fprintf(f, "Version Status: OUTDATED\n")
				if analysis.LatestVersion != "" {
					fmt.Fprintf(f, "Latest Version: %s\n", analysis.LatestVersion)
				}
			} else if analysis.LatestVersion != "" {
				fmt.Fprintf(f, "Version Status: UP-TO-DATE\n")
			} else {
				fmt.Fprintf(f, "Version Status: UNKNOWN\n")
			}

			// Vulnerabilities
			fmt.Fprintf(f, "\nVulnerabilities Found: %d\n", len(analysis.Vulnerabilities))
			if len(analysis.Vulnerabilities) > 0 {
				for i, cve := range analysis.Vulnerabilities {
					fmt.Fprintf(f, "  %d. %s\n", i+1, cve)
				}
			}

			// Exploitability
			fmt.Fprintf(f, "\nExploitability: %s\n", analysis.Exploitability)
			fmt.Fprintf(f, "\n%s\n\n", strings.Repeat("─", 63))
		}
	}

	// Write summary to file
	fmt.Fprintf(f, "\n%s\n", strings.Repeat("═", 63))
	fmt.Fprintf(f, "\nSaved to: %s\n", analysisFile)

	s.log(fmt.Sprintf("AI analysis completed: %d vulnerabilities found", totalVulns))
	fmt.Printf("\nSaved to: %s\n", Green(analysisFile))

	return totalVulns
}

// generateOutputs generates output files in requested formats
func (s *Scanner) generateOutputs(outputPath string) error {
	// Default to json,txt if not specified
	formats := s.Config.OutputFormats
	if formats == "" {
		formats = "json,txt"
	}

	formatList := strings.Split(formats, ",")

	for _, format := range formatList {
		format = strings.TrimSpace(strings.ToLower(format))

		switch format {
		case "json":
			jsonFormatter := formatter.NewJSONFormatter(outputPath)
			if err := jsonFormatter.Format(s.scanResult); err != nil {
				return fmt.Errorf("JSON format failed: %v", err)
			}
			s.log("Generated JSON output: scan_results.json")

		case "txt", "text":
			txtFormatter := formatter.NewTXTFormatter(outputPath)
			if err := txtFormatter.Format(s.scanResult); err != nil {
				return fmt.Errorf("TXT format failed: %v", err)
			}
			s.log("Generated TXT output: scan_results.txt")

		case "csv":
			csvFormatter := formatter.NewCSVFormatter(outputPath)
			if err := csvFormatter.Format(s.scanResult); err != nil {
				return fmt.Errorf("CSV format failed: %v", err)
			}
			if s.scanResult.Subdomains.APICount > 0 {
				s.log("Generated CSV outputs: subdomains.csv, api_endpoints.csv, scan_summary.csv")
			} else {
				s.log("Generated CSV outputs: subdomains.csv, scan_summary.csv")
			}
		}
	}

	return nil
}

// runPhase7DeepAIAnalysis runs comprehensive AI-powered security analysis
func (s *Scanner) runPhase7DeepAIAnalysis(outputPath string, subdomains []string) error {
	scanStart := time.Now()

	// Show AI Security Analysis header immediately
	if s.Config.EnableAI {
		terminal.PrintSectionHeader("AI DEEP SECURITY ANALYSIS")
		terminal.PrintSectionDivider()
		fmt.Println()

		// Initialize AI analyzer
		aiModel := "deepseek-r1:8b"
		deepMode := true // Always use deep mode when AI is enabled
		analyzer := intelligence.NewSecurityAnalyzer(aiModel, deepMode)

		// Check Ollama availability
		if !analyzer.IsAvailable(s.ctx) {
			terminal.PrintInfo("Ollama server not running, starting it now...")
			cmd := exec.Command("ollama", "serve")
			if err := cmd.Start(); err != nil {
				terminal.PrintAINotAvailable("Failed to start Ollama server")
				terminal.PrintError(fmt.Sprintf("Error: %v", err))
				terminal.PrintInfo("Please start Ollama manually: ollama serve")
				return nil
			}
			terminal.PrintSuccess("Ollama server started successfully")
			terminal.PrintInfo("Waiting for Ollama to initialize...")
			time.Sleep(3 * time.Second)
			if !analyzer.IsAvailable(s.ctx) {
				terminal.PrintAINotAvailable("Ollama service failed to start")
				return nil
			}
		}

		// Run integrated security analysis with AI
		s.runIntegratedSecurityAnalysis(outputPath, subdomains, analyzer)
	} else {
		// Run security checks without AI - just show basic summary
		terminal.PrintInfo("Running security checks without AI analysis...")
		terminal.PrintInfo("Enable --enable-ai for detailed AI-powered analysis")
		fmt.Println()
	}

	fmt.Println()
	terminal.PrintSectionDivider()
	terminal.PrintSuccess(fmt.Sprintf("Deep AI Security Analysis completed in %s", time.Since(scanStart)))
	terminal.PrintSectionDivider()
	fmt.Println()


	return nil
}

// runTechnologyFingerprinting performs technology fingerprinting
func (s *Scanner) runTechnologyFingerprinting(subdomains []string) map[string][]fingerprint.Technology {
	scanner := fingerprint.NewScanner(10)
	results := make(map[string][]fingerprint.Technology)

	for _, subdomain := range subdomains {
		select {
		case <-s.ctx.Done():
			return results
		default:
		}

		techs := scanner.DetectTechnologies(s.ctx, subdomain)
		if len(techs) > 0 {
			results[subdomain] = techs
		}
	}

	return results
}

// runSecurityHeadersAnalysis performs security headers analysis
func (s *Scanner) runSecurityHeadersAnalysis(subdomains []string) map[string]*security.HeaderAnalysis {
	analyzer := security.NewAnalyzer(10)
	results := make(map[string]*security.HeaderAnalysis)

	for _, subdomain := range subdomains {
		select {
		case <-s.ctx.Done():
			return results
		default:
		}

		analysis := analyzer.AnalyzeHeaders(s.ctx, subdomain)
		if analysis != nil {
			results[subdomain] = analysis
		}
	}

	return results
}

// runTLSAnalysis performs TLS/SSL analysis
func (s *Scanner) runTLSAnalysis(subdomains []string) map[string]*tls.Analysis {
	analyzer := tls.NewAnalyzer(5) // Reduced from 10s to 5s
	results := make(map[string]*tls.Analysis)

	for _, subdomain := range subdomains {
		select {
		case <-s.ctx.Done():
			return results
		default:
		}

		analysis := analyzer.Analyze(s.ctx, subdomain)
		if analysis != nil && analysis.Enabled {
			results[subdomain] = analysis
		}
	}

	return results
}

// runTakeoverDetection performs subdomain takeover detection
func (s *Scanner) runTakeoverDetection(subdomains []string) []takeover.Vulnerability {
	checker := takeover.NewChecker(5) // Reduced from 10s to 5s
	var vulns []takeover.Vulnerability

	for _, subdomain := range subdomains {
		select {
		case <-s.ctx.Done():
			return vulns
		default:
		}

		vuln := checker.CheckSubdomain(s.ctx, subdomain)
		if vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	return vulns
}

// runCloudDiscovery performs cloud asset discovery
func (s *Scanner) runCloudDiscovery() []cloud.Asset {
	scanner := cloud.NewScanner(s.Config.Domain, 2) // Reduced to 2s for faster scanning
	return scanner.ScanAll(s.ctx)
}

// runAPIDiscovery performs API intelligence discovery
func (s *Scanner) runAPIDiscovery(subdomains []string) map[string][]api.Finding {
	scanner := api.NewScanner(5) // Reduced from 10s to 5s
	results := make(map[string][]api.Finding)

	for _, subdomain := range subdomains {
		select {
		case <-s.ctx.Done():
			return results
		default:
		}

		findings := scanner.ScanSubdomain(s.ctx, subdomain)
		if len(findings) > 0 {
			results[subdomain] = findings
		}
	}

	return results
}

// runCORSDetection performs CORS misconfiguration detection
func (s *Scanner) runCORSDetection(subdomains []string) map[string][]cors.Issue {
	checker := cors.NewChecker(5) // Reduced from 10s to 5s
	results := make(map[string][]cors.Issue)

	for _, subdomain := range subdomains {
		select {
		case <-s.ctx.Done():
			return results
		default:
		}

		issues := checker.CheckSubdomain(s.ctx, subdomain)
		if len(issues) > 0 {
			results[subdomain] = issues
		}
	}

	return results
}

// runSecretsScanning performs JS secrets scanning
func (s *Scanner) runSecretsScanning(subdomains []string) map[string][]secrets.Finding {
	scanner := secrets.NewScanner(5) // Reduced from 10s to 5s
	results := make(map[string][]secrets.Finding)

	for _, subdomain := range subdomains {
		select {
		case <-s.ctx.Done():
			return results
		default:
		}

		findings := scanner.ScanSubdomain(s.ctx, subdomain)
		if len(findings) > 0 {
			results[subdomain] = findings
		}
	}

	return results
}

// saveDeepAnalysisResults saves results to files
func (s *Scanner) saveDeepAnalysisResults(outputPath string, secretResults map[string][]secrets.Finding,
	takeoverVulns []takeover.Vulnerability, cloudAssets []cloud.Asset) {

	// Save secrets with JS file URLs
	if len(secretResults) > 0 {
		secretsFile := filepath.Join(outputPath, "secrets_found.txt")
		var allFindings []secrets.Finding
		for _, findings := range secretResults {
			allFindings = append(allFindings, findings...)
		}
		content := secrets.FormatForSave(allFindings)
		SaveToFile(secretsFile, []byte(content))
		s.log(fmt.Sprintf("Saved secrets to %s", secretsFile))
	}

	// Save takeover vulnerabilities
	if len(takeoverVulns) > 0 {
		takeoverFile := filepath.Join(outputPath, "takeover_vulns.txt")
		var content strings.Builder
		content.WriteString("=== SUBDOMAIN TAKEOVER VULNERABILITIES ===\n\n")
		for _, vuln := range takeoverVulns {
			content.WriteString(fmt.Sprintf("[%s] %s\n", strings.ToUpper(vuln.Severity), vuln.Subdomain))
			content.WriteString(fmt.Sprintf("  Service: %s\n", vuln.Service))
			content.WriteString(fmt.Sprintf("  CNAME: %s\n", vuln.CNAME))
			content.WriteString(fmt.Sprintf("  Evidence: %s\n\n", vuln.Evidence))
		}
		SaveToFile(takeoverFile, []byte(content.String()))
		s.log(fmt.Sprintf("Saved takeover vulnerabilities to %s", takeoverFile))
	}

	// Save cloud assets
	if len(cloudAssets) > 0 {
		cloudFile := filepath.Join(outputPath, "cloud_assets.txt")
		var content strings.Builder
		content.WriteString("=== CLOUD ASSETS ===\n\n")
		for _, asset := range cloudAssets {
			status := asset.Status
			if asset.IsWritable {
				status = "PUBLIC + WRITABLE (CRITICAL)"
			}
			content.WriteString(fmt.Sprintf("[%s] %s (%s)\n", asset.Type, asset.Name, asset.Provider))
			content.WriteString(fmt.Sprintf("  Status: %s\n", status))
			content.WriteString(fmt.Sprintf("  URL: %s\n", asset.URL))
			if len(asset.Contents) > 0 {
				maxFiles := 5
				if len(asset.Contents) < maxFiles {
					maxFiles = len(asset.Contents)
				}
				content.WriteString(fmt.Sprintf("  Files: %s\n", strings.Join(asset.Contents[:maxFiles], ", ")))
			}
			content.WriteString("\n")
		}
		SaveToFile(cloudFile, []byte(content.String()))
		s.log(fmt.Sprintf("Saved cloud assets to %s", cloudFile))
	}
}

// log adds a line to the terminal capture
func (s *Scanner) log(message string) {
	s.termCapture.AddLine(message)
}

// writeLinesToFile writes lines to a file
func writeLinesToFile(filePath string, lines []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := fmt.Fprintln(file, line); err != nil {
			return err
		}
	}

	return nil
}

// readLinesFromFile reads lines from a file
func readLinesFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}

	return result, nil
}

// SaveToFile saves bytes to a file (exported for Phase 6 to use)
func SaveToFile(filePath string, data []byte) error {
	return os.WriteFile(filePath, data, 0644)
}

// runAISecurityAnalysis runs AI analysis on all security findings
func (s *Scanner) runAISecurityAnalysis(outputPath string, securityResults map[string]*security.HeaderAnalysis, tlsResults map[string]*tls.Analysis, takeoverVulns []takeover.Vulnerability, corsResults map[string][]cors.Issue, secretResults map[string][]secrets.Finding, cloudAssets []cloud.Asset) {

	// Create AI analyzer - always use deep mode when AI is enabled
	aiModel := "deepseek-r1:8b"
	deepMode := true // Always use deep mode when AI is enabled
	analyzer := intelligence.NewSecurityAnalyzer(aiModel, deepMode)

	// Check Ollama availability and start if not running
	if !analyzer.IsAvailable(s.ctx) {
		terminal.PrintInfo("Ollama server not running, starting it now...")

		// Start Ollama server in background
		cmd := exec.Command("ollama", "serve")
		err := cmd.Start()
		if err != nil {
			terminal.PrintAINotAvailable("Failed to start Ollama server")
			terminal.PrintError(fmt.Sprintf("Error: %v", err))
			terminal.PrintInfo("Please start Ollama manually: ollama serve")
			return
		}

		terminal.PrintSuccess("Ollama server started successfully")

		// Wait a few seconds for Ollama to initialize
		terminal.PrintInfo("Waiting for Ollama to initialize...")
		time.Sleep(3 * time.Second)

		// Check again if Ollama is now available
		if !analyzer.IsAvailable(s.ctx) {
			terminal.PrintAINotAvailable("Ollama service failed to start")
			return
		}
	}

	terminal.PrintAIAnalysisStart(aiModel)

	// Collect all findings
	var findings []intelligence.SecurityFinding

	// 1. Security Headers findings
	for subdomain, analysis := range securityResults {
		if analysis.Grade == "D" || analysis.Grade == "F" {
			findings = append(findings, intelligence.SecurityFinding{
				Type:        "Security Headers",
				Subdomain:   subdomain,
				Severity:    "HIGH",
				Description: fmt.Sprintf("Poor security headers (Grade: %s). Missing: %v", analysis.Grade, analysis.MissingHeaders),
			})
		}
	}

	// 2. TLS/SSL findings
	for subdomain, analysis := range tlsResults {
		if len(analysis.Vulnerabilities) > 0 {
			findings = append(findings, intelligence.SecurityFinding{
				Type:        "TLS/SSL",
				Subdomain:   subdomain,
				Severity:    "HIGH",
				Description: fmt.Sprintf("TLS vulnerabilities found: %v", analysis.Vulnerabilities),
			})
		}
	}

	// 3. Subdomain Takeover findings
	for _, vuln := range takeoverVulns {
		severity := "CRITICAL"
		// Map takeover severity to analysis severity
		if vuln.Severity == "high" {
			severity = "HIGH"
		} else if vuln.Severity == "medium" {
			severity = "MODERATE"
		} else if vuln.Severity == "low" {
			severity = "LOW"
		}
		findings = append(findings, intelligence.SecurityFinding{
			Type:        "Subdomain Takeover",
			Subdomain:   vuln.Subdomain,
			Severity:    severity,
			Description: fmt.Sprintf("Potential takeover via %s: %s", vuln.Service, vuln.Evidence),
		})
	}

	// 4. CORS Misconfiguration findings
	for subdomain, issues := range corsResults {
		for _, issue := range issues {
			severity := "MODERATE"
			if issue.Severity == "critical" {
				severity = "CRITICAL"
			} else if issue.Severity == "high" {
				severity = "HIGH"
			}
			findings = append(findings, intelligence.SecurityFinding{
				Type:        "CORS Misconfiguration",
				Subdomain:   subdomain,
				Severity:    severity,
				Description: issue.Description,
			})
		}
	}

	// 5. Secrets findings
	for subdomain, secrets := range secretResults {
		for _, secret := range secrets {
			severity := "HIGH"
			if secret.Severity == "critical" {
				severity = "CRITICAL"
			}
			findings = append(findings, intelligence.SecurityFinding{
				Type:        "Exposed Secret",
				Subdomain:   subdomain,
				Severity:    severity,
				Description: fmt.Sprintf("%s found in %s (line %d)", secret.Type, secret.Source, secret.LineNumber),
			})
		}
	}

	// 6. Cloud Asset findings
	for _, asset := range cloudAssets {
		if asset.IsWritable {
			findings = append(findings, intelligence.SecurityFinding{
				Type:        "Cloud Security",
				Subdomain:   asset.URL,
				Severity:    "CRITICAL",
				Description: fmt.Sprintf("Publicly writable %s bucket", asset.Provider),
			})
		} else if asset.Status == "public" {
			findings = append(findings, intelligence.SecurityFinding{
				Type:        "Cloud Security",
				Subdomain:   asset.URL,
				Severity:    "MODERATE",
				Description: fmt.Sprintf("Public %s bucket (read-only)", asset.Provider),
			})
		}
	}

	if len(findings) == 0 {
		terminal.PrintInfo("No significant security findings to analyze")
		return
	}

	terminal.PrintInfo(fmt.Sprintf("Analyzing %d security findings...", len(findings)))
	fmt.Println()

	// Analyze each finding
	var criticalCount, highCount, moderateCount, lowCount int
	var analysisResults []string

	for _, finding := range findings {
		result, err := analyzer.AnalyzeFinding(s.ctx, finding)
		if err != nil {
			continue
		}

		// Count by risk level
		switch result.RiskLevel {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MODERATE":
			moderateCount++
		case "LOW":
			lowCount++
		}

		// Display analysis (with deep mode data if available)
		terminal.PrintSecurityFindingAnalysis(
			result.Finding.Type,
			result.Finding.Subdomain,
			result.RiskLevel,
			result.Exploitability,
			result.CVEs,
			result.AttackChain, // Show attack chain in deep mode
			result.POC,         // Show POC in deep mode
		)

		// Save to results (include deep mode data)
		cvesStr := "None"
		if len(result.CVEs) > 0 {
			cvesStr = strings.Join(result.CVEs, ", ")
		}

		resultText := fmt.Sprintf(
			"[%s] %s - %s\nRisk: %s\nExploitability: %s\nCVEs: %s\n",
			result.Finding.Type,
			result.Finding.Subdomain,
			result.RiskLevel,
			result.Exploitability,
			cvesStr,
		)

		// Add deep mode information if available
		if result.AttackChain != "" {
			resultText += fmt.Sprintf("Attack Chain: %s\n", result.AttackChain)
		}
		if result.POC != "" {
			resultText += fmt.Sprintf("Proof of Concept:\n%s\n", result.POC)
		}

		analysisResults = append(analysisResults, resultText)
	}

	// Print summary
	terminal.PrintSecurityAnalysisSummary(
		len(findings),
		criticalCount,
		highCount,
		moderateCount,
		lowCount,
		"",
	)

	// Save to file
	if outputPath != "" {
		analysisFile := filepath.Join(outputPath, "security_ai_analysis.txt")
		content := strings.Join(analysisResults, "\n---\n\n")
		if err := os.WriteFile(analysisFile, []byte(content), 0644); err == nil {
			terminal.PrintSuccess(fmt.Sprintf("AI analysis saved to: %s", analysisFile))
		}
	}
}

// shutdownOllama stops the Ollama server to free up resources
func (s *Scanner) shutdownOllama() {
	fmt.Println()
	terminal.PrintInfo("Stopping Ollama server to free up resources...")

	// Try to gracefully stop Ollama
	cmd := exec.Command("pkill", "-f", "ollama")
	if err := cmd.Run(); err != nil {
		// Try Windows equivalent
		cmd = exec.Command("taskkill", "/F", "/IM", "ollama.exe")
		if err := cmd.Run(); err != nil {
			terminal.PrintWarning("Failed to stop Ollama server automatically")
			terminal.PrintInfo("You can manually stop it with: pkill ollama (Linux/Mac) or taskkill /F /IM ollama.exe (Windows)")
			return
		}
	}

	terminal.PrintSuccess("Ollama server stopped successfully")
	fmt.Println()
}

// SubdomainSecurityData holds all security check results for a subdomain
type SubdomainSecurityData struct {
	Subdomain       string
	StatusCode      int
	HeadersGrade    string
	MissingHeaders  []string
	HeadersRisk     string
	TLSVulns        []string
	TLSRisk         string
	TakeoverVuln    *takeover.Vulnerability
	TakeoverRisk    string
	CloudAssets     []cloud.Asset
	CloudRisk       string
	CORSIssues      []cors.Issue
	CORSRisk        string
	Secrets         []secrets.Finding
	SecretsRisk     string
}

// runIntegratedSecurityAnalysis runs security checks grouped by subdomain with real-time AI analysis
func (s *Scanner) runIntegratedSecurityAnalysis(outputPath string, subdomains []string, analyzer *intelligence.SecurityAnalyzer) {
	var criticalCount, highCount, moderateCount, lowCount int

	// Deduplicate subdomains (www.example.com and example.com are same)
	uniqueSubdomains := s.deduplicateSubdomains(subdomains)

	// Process each subdomain individually - run checks and AI analysis immediately
	for _, subdomain := range uniqueSubdomains {
		data := &SubdomainSecurityData{
			Subdomain:      subdomain,
			StatusCode:     s.getStatusCode(subdomain),
			MissingHeaders: []string{},
			TLSVulns:       []string{},
			CloudAssets:    []cloud.Asset{},
			CORSIssues:     []cors.Issue{},
			Secrets:        []secrets.Finding{},
		}

		// Print subdomain header
		terminal.PrintSubdomainHeader(data.Subdomain, data.StatusCode)

		var findings []intelligence.SecurityFinding

		// 1. Security Headers - run check immediately
		securityResults := s.runSecurityHeadersAnalysis([]string{subdomain})
		if analysis, exists := securityResults[subdomain]; exists {
			data.HeadersGrade = analysis.Grade
			data.MissingHeaders = analysis.MissingHeaders
			data.HeadersRisk = s.calculateHeadersRisk(analysis.Grade)

			if data.HeadersGrade != "" || len(data.MissingHeaders) > 0 {
				terminal.PrintSecurityHeadersResult(data.HeadersGrade, data.MissingHeaders, data.HeadersRisk)

				// Add to findings for AI if poor grade
				if data.HeadersGrade == "D" || data.HeadersGrade == "F" {
					findings = append(findings, intelligence.SecurityFinding{
						Type:        "Security Headers",
						Subdomain:   subdomain,
						Severity:    data.HeadersRisk,
						Description: fmt.Sprintf("Poor security headers (Grade: %s), Missing: %s", data.HeadersGrade, strings.Join(data.MissingHeaders, ", ")),
					})
				}
			}
		}

		// 2. TLS/SSL - run check immediately
		tlsResults := s.runTLSAnalysis([]string{subdomain})
		if analysis, exists := tlsResults[subdomain]; exists {
			data.TLSVulns = analysis.Vulnerabilities
			data.TLSRisk = s.calculateTLSRisk(analysis.Vulnerabilities)

			if len(data.TLSVulns) > 0 {
				terminal.PrintTLSResult(analysis.Version, data.TLSVulns, data.TLSRisk)

				for _, vuln := range data.TLSVulns {
					findings = append(findings, intelligence.SecurityFinding{
						Type:        "TLS/SSL",
						Subdomain:   subdomain,
						Severity:    data.TLSRisk,
						Description: vuln,
					})
				}
			}
		}

		// 3. Subdomain Takeover - run check immediately
		takeoverVulns := s.runTakeoverDetection([]string{subdomain})
		if len(takeoverVulns) > 0 {
			vuln := takeoverVulns[0]
			data.TakeoverVuln = &vuln
			if strings.ToUpper(vuln.Severity) == "CRITICAL" {
				data.TakeoverRisk = "CRITICAL"
			} else if strings.ToUpper(vuln.Severity) == "HIGH" {
				data.TakeoverRisk = "HIGH"
			} else {
				data.TakeoverRisk = "MEDIUM"
			}

			terminal.PrintTakeoverResult(true, vuln.Service, vuln.Evidence, data.TakeoverRisk)

			findings = append(findings, intelligence.SecurityFinding{
				Type:        "Subdomain Takeover",
				Subdomain:   subdomain,
				Severity:    data.TakeoverRisk,
				Description: fmt.Sprintf("%s service vulnerable: %s", vuln.Service, vuln.Evidence),
			})
		}

		// 4. Cloud Assets - check for this subdomain
		cloudAssets := s.runCloudDiscovery()
		for _, asset := range cloudAssets {
			if s.extractSubdomainFromURL(asset.URL) == subdomain {
				data.CloudAssets = append(data.CloudAssets, asset)
			}
		}
		if len(data.CloudAssets) > 0 {
			data.CloudRisk = s.calculateCloudRisk(data.CloudAssets)
			for _, asset := range data.CloudAssets {
				terminal.PrintCloudAssetResult(asset.Provider, asset.URL, asset.Status, asset.IsWritable, data.CloudRisk)

				if asset.IsWritable || asset.Status == "public" {
					findings = append(findings, intelligence.SecurityFinding{
						Type:        "Cloud Asset",
						Subdomain:   subdomain,
						Severity:    data.CloudRisk,
						Description: fmt.Sprintf("Public %s bucket: %s (%s)", asset.Provider, asset.URL, asset.Status),
					})
				}
			}
		}

		// 5. CORS - run check immediately
		corsResults := s.runCORSDetection([]string{subdomain})
		if issues, exists := corsResults[subdomain]; exists {
			data.CORSIssues = issues
			data.CORSRisk = s.calculateCORSRisk(issues)

			if len(data.CORSIssues) > 0 {
				issueDescriptions := make([]string, 0, len(data.CORSIssues))
				for _, issue := range data.CORSIssues {
					issueDescriptions = append(issueDescriptions, issue.Description)

					findings = append(findings, intelligence.SecurityFinding{
						Type:        "CORS",
						Subdomain:   subdomain,
						Severity:    strings.ToUpper(issue.Severity),
						Description: issue.Description,
					})
				}
				terminal.PrintCORSResult(issueDescriptions, data.CORSRisk)
			}
		}

		// 6. Secrets - run check immediately
		secretResults := s.runSecretsScanning([]string{subdomain})
		for url, secretFindings := range secretResults {
			if s.extractSubdomainFromURL(url) == subdomain {
				data.Secrets = append(data.Secrets, secretFindings...)
			}
		}
		if len(data.Secrets) > 0 {
			data.SecretsRisk = s.calculateSecretsRisk(data.Secrets)
			for _, secret := range data.Secrets {
				terminal.PrintSecretsResult(secret.Type, secret.Source, secret.Match, strings.ToUpper(secret.Severity))

				findings = append(findings, intelligence.SecurityFinding{
					Type:        "Secret Exposure",
					Subdomain:   subdomain,
					Severity:    strings.ToUpper(secret.Severity),
					Description: fmt.Sprintf("%s found at %s", secret.Type, secret.Source),
				})
			}
		}

		// AI Analysis for this subdomain's findings (collected above)
		if analyzer != nil && len(findings) > 0 {
			// Run AI analysis silently - don't show messages or errors
			for _, finding := range findings {
				result, err := analyzer.AnalyzeFinding(s.ctx, finding)
				if err != nil {
					// Skip failed analysis silently
					continue
				}

				// Display AI analysis
				terminal.PrintSecurityFindingAnalysis(
					result.Finding.Type,
					result.Finding.Subdomain,
					result.RiskLevel,
					result.Exploitability,
					result.CVEs,
					result.AttackChain,
					result.POC,
				)
			}
		}

		// Count risks for summary
		risks := []string{data.HeadersRisk, data.TLSRisk, data.TakeoverRisk, data.CloudRisk, data.CORSRisk, data.SecretsRisk}
		for _, risk := range risks {
			switch risk {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				moderateCount++
			case "LOW":
				lowCount++
			}
		}
	}

	// Print final summary
	totalFindings := criticalCount + highCount + moderateCount + lowCount
	terminal.PrintFinalSecuritySummary(totalFindings, criticalCount, highCount, moderateCount, lowCount)
}

// getStatusCode fetches HTTP status code for a subdomain
func (s *Scanner) getStatusCode(subdomain string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try HTTPS first
	url := "https://" + subdomain
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0
	}

	// Add proper headers to avoid 406 errors
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		// Try HTTP if HTTPS fails
		url = "http://" + subdomain
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return 0
		}

		// Add headers for HTTP request too
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err = client.Do(req)
		if err != nil {
			return 0
		}
	}
	defer resp.Body.Close()

	return resp.StatusCode
}

// calculateHeadersRisk calculates risk level from security headers grade
func (s *Scanner) calculateHeadersRisk(grade string) string {
	switch grade {
	case "A", "A+":
		return "LOW"
	case "B":
		return "LOW"
	case "C":
		return "MEDIUM"
	case "D":
		return "HIGH"
	case "F":
		return "CRITICAL"
	default:
		return "MEDIUM"
	}
}

// calculateTLSRisk calculates risk level from TLS vulnerabilities
func (s *Scanner) calculateTLSRisk(vulns []string) string {
	if len(vulns) == 0 {
		return "LOW"
	}

	// Check for critical TLS issues
	for _, vuln := range vulns {
		lowerVuln := strings.ToLower(vuln)
		if strings.Contains(lowerVuln, "sslv2") || strings.Contains(lowerVuln, "sslv3") {
			return "CRITICAL"
		}
		if strings.Contains(lowerVuln, "tls 1.0") || strings.Contains(lowerVuln, "tls 1.1") {
			return "HIGH"
		}
	}

	return "MEDIUM"
}

// calculateCloudRisk calculates risk level from cloud assets
func (s *Scanner) calculateCloudRisk(assets []cloud.Asset) string {
	if len(assets) == 0 {
		return "LOW"
	}

	for _, asset := range assets {
		if asset.IsWritable {
			return "CRITICAL"
		}
		if asset.Status == "public" {
			return "MEDIUM"
		}
	}

	return "LOW"
}

// calculateCORSRisk calculates risk level from CORS issues
func (s *Scanner) calculateCORSRisk(issues []cors.Issue) string {
	if len(issues) == 0 {
		return "LOW"
	}

	maxRisk := "LOW"
	for _, issue := range issues {
		severity := strings.ToUpper(issue.Severity)
		if severity == "CRITICAL" {
			return "CRITICAL"
		}
		if severity == "HIGH" && maxRisk != "CRITICAL" {
			maxRisk = "HIGH"
		}
		if severity == "MEDIUM" && maxRisk != "HIGH" && maxRisk != "CRITICAL" {
			maxRisk = "MEDIUM"
		}
	}

	return maxRisk
}

// calculateSecretsRisk calculates risk level from secrets
func (s *Scanner) calculateSecretsRisk(secretsFindings []secrets.Finding) string {
	if len(secretsFindings) == 0 {
		return "LOW"
	}

	maxRisk := "LOW"
	for _, secret := range secretsFindings {
		severity := strings.ToUpper(secret.Severity)
		if severity == "CRITICAL" {
			return "CRITICAL"
		}
		if severity == "HIGH" && maxRisk != "CRITICAL" {
			maxRisk = "HIGH"
		}
		if severity == "MEDIUM" && maxRisk != "HIGH" && maxRisk != "CRITICAL" {
			maxRisk = "MEDIUM"
		}
	}

	return maxRisk
}

// extractSubdomainFromURL extracts the subdomain/hostname from a URL
func (s *Scanner) extractSubdomainFromURL(rawURL string) string {
	// Remove protocol
	url := strings.TrimPrefix(rawURL, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Remove path
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	// Remove port
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// deduplicateSubdomains removes duplicate subdomains (www.example.com and example.com)
func (s *Scanner) deduplicateSubdomains(subdomains []string) []string {
	seen := make(map[string]bool)
	unique := []string{}

	for _, subdomain := range subdomains {
		// Normalize: remove www. prefix for comparison
		normalized := strings.TrimPrefix(strings.ToLower(subdomain), "www.")

		// If we haven't seen this base domain, add the original
		if !seen[normalized] {
			seen[normalized] = true
			unique = append(unique, subdomain)
		}
	}

	return unique
}

// getSubdomainInfo gathers detailed information about a subdomain
func (s *Scanner) getSubdomainInfo(subdomain string) terminal.SubdomainInfo {
	info := terminal.SubdomainInfo{
		Subdomain:   subdomain,
		StatusCode:  s.getStatusCode(subdomain),
		IP:          "",
		CNAME:       "",
		Location:    "",
		PTR:         "",
		MX:          []string{},
		TLSAltNames: []string{},
		TechStack:   []string{},
	}

	// Get IP address
	if ips, err := s.lookupIP(subdomain); err == nil && len(ips) > 0 {
		info.IP = ips[0]

		// Get PTR record
		if ptr, err := s.lookupPTR(info.IP); err == nil && ptr != "" {
			info.PTR = ptr
		}

		// Get location info
		if location, err := s.getIPLocation(info.IP); err == nil && location != "" {
			info.Location = location
		}
	}

	// Get CNAME record
	if cname, err := s.lookupCNAME(subdomain); err == nil && cname != "" {
		info.CNAME = cname
	}

	// Get MX records
	if mx, err := s.lookupMX(subdomain); err == nil && len(mx) > 0 {
		info.MX = mx
	}

	// Get TLS Alt Names from certificate
	if altNames, err := s.getTLSAltNames(subdomain); err == nil && len(altNames) > 0 {
		info.TLSAltNames = altNames
	}

	// Get technology stack
	if techs, err := s.getTechStack(subdomain); err == nil && len(techs) > 0 {
		info.TechStack = techs
	}

	return info
}

// lookupIP performs DNS A/AAAA lookup
func (s *Scanner) lookupIP(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	return ips, nil
}

// lookupCNAME performs DNS CNAME lookup
func (s *Scanner) lookupCNAME(domain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return "", err
	}

	// Remove trailing dot and return only if different from original
	cname = strings.TrimSuffix(cname, ".")
	if cname == domain {
		return "", nil
	}

	return cname, nil
}

// lookupPTR performs reverse DNS lookup
func (s *Scanner) lookupPTR(ip string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "", err
	}

	// Return first PTR record, remove trailing dot
	return strings.TrimSuffix(names[0], "."), nil
}

// lookupMX performs MX record lookup
func (s *Scanner) lookupMX(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}

	var mxHosts []string
	for _, mx := range mxRecords {
		mxHosts = append(mxHosts, strings.TrimSuffix(mx.Host, "."))
	}

	return mxHosts, nil
}

// getTLSAltNames extracts Subject Alternative Names from TLS certificate
func (s *Scanner) getTLSAltNames(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try HTTPS connection
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := cryptotls.DialWithDialer(dialer, "tcp", domain+":443", &cryptotls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Check context
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Get certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	// Extract SANs (Subject Alternative Names)
	cert := certs[0]
	altNames := make([]string, 0)

	// Add DNS names from SAN
	for _, name := range cert.DNSNames {
		if name != domain && !strings.HasPrefix(name, "*.") {
			altNames = append(altNames, name)
		}
	}

	return altNames, nil
}

// getTechStack detects technology stack using fingerprinting
func (s *Scanner) getTechStack(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scanner := fingerprint.NewScanner(1)
	techs := scanner.DetectTechnologies(ctx, "https://"+domain)

	if len(techs) == 0 {
		return nil, nil
	}

	techNames := make([]string, 0, len(techs))
	for _, tech := range techs {
		techNames = append(techNames, tech.Name)
	}

	return techNames, nil
}

// getIPLocation gets geolocation for an IP address
func (s *Scanner) getIPLocation(ip string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Use ip-api.com for free geolocation (no API key required)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=city,country", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		City    string `json:"city"`
		Country string `json:"country"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.City != "" && result.Country != "" {
		return fmt.Sprintf("%s, %s", result.City, result.Country), nil
	} else if result.Country != "" {
		return result.Country, nil
	}

	return "", nil
}

// ensureOllamaRunning checks if Ollama is running and starts it if needed
func (s *Scanner) ensureOllamaRunning() {
	// Check if Ollama is already running
	resp, err := http.Get("http://localhost:11434/api/tags")
	if err == nil {
		resp.Body.Close()
		// Ollama is running, check if model exists
		s.checkDeepSeekModel()
		return
	}

	// Ollama not running, try to start it
	terminal.PrintInfo("Ollama not running, attempting to start...")

	// Try to start Ollama service
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// On Windows, start Ollama in background
		cmd = exec.Command("cmd", "/C", "start", "/B", "ollama", "serve")
	} else {
		// On Linux/Mac, start Ollama in background
		cmd = exec.Command("ollama", "serve")
		cmd.Stdout = nil
		cmd.Stderr = nil
	}

	if err := cmd.Start(); err != nil {
		terminal.PrintError(fmt.Sprintf("Failed to start Ollama: %v", err))
		terminal.PrintInfo("Please start Ollama manually: ollama serve")
		terminal.PrintInfo("Then run the scan again")
		os.Exit(1)
	}

	// Wait a few seconds for Ollama to start
	terminal.PrintInfo("Waiting for Ollama to start...")
	time.Sleep(3 * time.Second)

	// Check if it started successfully
	resp, err = http.Get("http://localhost:11434/api/tags")
	if err != nil {
		terminal.PrintError("Ollama started but not responding")
		terminal.PrintInfo("Please start Ollama manually: ollama serve")
		terminal.PrintInfo("Then run the scan again")
		os.Exit(1)
	}
	resp.Body.Close()

	terminal.PrintSuccess("Ollama started successfully")
	s.checkDeepSeekModel()
}

// checkDeepSeekModel checks if deepseek-r1:7b model is installed and exits if not found
func (s *Scanner) checkDeepSeekModel() {
	resp, err := http.Get("http://localhost:11434/api/tags")
	if err != nil {
		terminal.PrintError("Failed to connect to Ollama API")
		terminal.PrintInfo("Install with: ollama pull deepseek-r1:7b")
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		terminal.PrintError("Failed to read Ollama models")
		os.Exit(1)
	}

	// Check if deepseek-r1:7b exists
	hasModel := false
	for _, model := range result.Models {
		if strings.Contains(model.Name, "deepseek-r1:7b") {
			hasModel = true
			break
		}
	}

	if !hasModel {
		terminal.PrintError("DeepSeek model not found - cannot proceed with Active Exploitation")
		terminal.PrintInfo("Install the model with: ollama pull deepseek-r1:7b")
		terminal.PrintInfo("This will download ~4.7GB and takes a few minutes")
		os.Exit(1)
	}

	terminal.PrintSuccess("DeepSeek model ready (deepseek-r1:7b)")
}
