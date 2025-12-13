package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/who0xac/pinakastra/pkg/api"
	"github.com/who0xac/pinakastra/pkg/asn"
	"github.com/who0xac/pinakastra/pkg/cloud"
	"github.com/who0xac/pinakastra/pkg/config"
	"github.com/who0xac/pinakastra/pkg/cors"
	"github.com/who0xac/pinakastra/pkg/cve"
	"github.com/who0xac/pinakastra/pkg/fingerprint"
	"github.com/who0xac/pinakastra/pkg/httpprobe"
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
	"github.com/who0xac/pinakastra/pkg/vhost"
	"github.com/who0xac/pinakastra/pkg/webui"
)

// ScanConfig holds the configuration for a scan
type ScanConfig struct {
	Domain        string
	OutputDir     string
	OutputFile    string
	OutputFormats string
	Mode          string
	EnableAI      bool
	AIDeep        bool
	Threads       int
	RateLimit     int
	UseTor        bool
	NoBruteforce  bool
	NoPortscan    bool
	Ports         string
	WebUI         bool
	WebPort       int
}

// Scanner handles the full scanning workflow
type Scanner struct {
	Config          *ScanConfig
	ctx             context.Context
	termCapture     *utils.TerminalCapture
	scanResult      *formatter.ScanResult
	startTime       time.Time
	webUIServer     *webui.Server
	webFiles        fs.FS
}

// NewScanner creates a new scanner instance
func NewScanner(config *ScanConfig, webFiles fs.FS) *Scanner {
	return &Scanner{
		Config:      config,
		ctx:         context.Background(),
		termCapture: utils.NewTerminalCapture(),
		startTime:   time.Now(),
		webFiles:    webFiles,
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

	// Start Web UI if enabled
	if s.Config.WebUI {
		s.webUIServer = webui.NewServer(s.Config.WebPort, s.Config.Domain, s.webFiles)
		go func() {
			if err := s.webUIServer.Start(); err != nil {
				s.log(fmt.Sprintf("Web UI error: %v", err))
			}
		}()
		// Send initial status
		s.sendStatusUpdate("Initializing", 1, 0, "Scan starting...")
	}

	// Initialize scan result
	s.scanResult = &formatter.ScanResult{
		Metadata: formatter.ScanMetadata{
			Domain:    s.Config.Domain,
			ScanID:    scanID,
			StartTime: s.startTime,
			Mode:      s.Config.Mode,
			EnableAI:  s.Config.EnableAI,
			AIDeep:    s.Config.AIDeep,
			UseTor:    s.Config.UseTor,
			Version:   "1.0.0",
		},
		Subdomains: formatter.SubdomainResults{
			ToolResults: make(map[string]int),
		},
		TerminalOutput: []string{},
	}

	// Phase 1: Subdomain Enumeration
	subdomains, err := s.runSubdomainEnumeration(outputPath)
	if err != nil {
		return fmt.Errorf("subdomain enumeration failed: %v", err)
	}

	// Phase 2: HTTP Probing
	_, err = s.runHTTPProbing(outputPath, subdomains)
	if err != nil {
		return fmt.Errorf("HTTP probing failed: %v", err)
	}

	// Phase 3: IP Resolution
	_, err = s.runIPResolution(outputPath)
	if err != nil {
		return fmt.Errorf("IP resolution failed: %v", err)
	}

	// Phase 4: URL Discovery
	_, err = s.runURLDiscovery(outputPath)
	if err != nil {
		return fmt.Errorf("URL discovery failed: %v", err)
	}

	// Port Scanning (optional, skip if --no-portscan)
	if !s.Config.NoPortscan {
		if err := s.runPortScan(outputPath); err != nil {
			s.log(fmt.Sprintf("Port scan warning: %v", err))
		}
	}

	// Deep Security Analysis
	if err := s.runPhase6DeepAnalysis(outputPath, subdomains); err != nil {
		s.log(fmt.Sprintf("Deep analysis warning: %v", err))
		// Don't fail the entire scan if deep analysis has issues
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

	// Send final completion status
	s.sendStatusUpdate("Scan Complete", 7, 100, fmt.Sprintf("All phases completed in %s", s.scanResult.Metadata.Duration))

	return nil
}

// runSubdomainEnumeration runs Phase 1: Subdomain Discovery
func (s *Scanner) runSubdomainEnumeration(outputPath string) ([]string, error) {
	phaseStart := time.Now()
	s.sendStatusUpdate("Subdomain Enumeration", 1, 0, "Starting subdomain discovery...")

	enumerator := subdomain.NewPassiveEnumerator(s.Config.Domain, outputPath)

	// Load configuration file for API keys
	cfg, err := config.LoadConfig()
	if err != nil {
		s.log(fmt.Sprintf("Warning: Could not load config: %v", err))
	}

	// Configure optional paths from config directory
	enumerator.AmassConfig = ""
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

	// Send subdomain updates to web UI
	for _, sub := range subdomains {
		s.sendSubdomainUpdate(sub, "", "discovered")
	}

	s.sendStatusUpdate("Subdomain Enumeration", 1, 100, fmt.Sprintf("Found %d subdomains", len(subdomains)))

	return subdomains, nil
}

// runHTTPProbing runs Phase 2: HTTP Probing
func (s *Scanner) runHTTPProbing(outputPath string, subdomains []string) ([]string, error) {
	phaseStart := time.Now()
	s.sendStatusUpdate("HTTP Probing", 2, 0, "Probing for live hosts...")

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

	s.sendStatusUpdate("HTTP Probing", 2, 100, fmt.Sprintf("Found %d live hosts", result.LiveCount))

	return result.LiveURLs, nil
}

// runIPResolution runs Phase 3: IP Resolution
func (s *Scanner) runIPResolution(outputPath string) (map[string][]string, error) {
	phaseStart := time.Now()
	s.sendStatusUpdate("IP Resolution", 3, 0, "Resolving IP addresses...")

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
	if err == nil && len(ips) > 0 {
		terminal.PrintPhaseStarting("Fetching ASN information")

		asnLookup := asn.NewLookup()
		asnResults, err := asnLookup.LookupBatch(s.ctx, ips)
		if err == nil && len(asnResults) > 0 {
			// Get statistics
			stats := asn.GetStatistics(asnResults)

			// Build display strings
			var topASNs []string
			for _, stat := range stats {
				asnStr := fmt.Sprintf("AS%s (%s): %d IPs", stat.ASN, stat.Description, stat.Count)
				topASNs = append(topASNs, asnStr)
			}

			// Print ASN summary
			terminal.PrintASNSummary(len(stats), topASNs)

			// Save ASN data to file
			asnFile := filepath.Join(outputPath, "asn_data.txt")
			s.saveASNData(asnFile, stats)

			s.log(fmt.Sprintf("ASN lookup completed: %d unique ASNs found", len(stats)))
		}
	}

	// Perform VHost discovery
	subdomainsFile := filepath.Join(outputPath, "subdomains.txt")
	if _, err := os.Stat(ipsOnlyFile); err == nil {
		if _, err := os.Stat(subdomainsFile); err == nil {
			terminal.PrintPhaseStarting("Virtual Host Discovery")

			vhostScanner := vhost.NewScanner(ipsOnlyFile, subdomainsFile, outputPath)
			vhostResults, err := vhostScanner.Run(s.ctx)
			if err == nil && len(vhostResults) > 0 {
				totalVHosts := 0
				for _, vr := range vhostResults {
					totalVHosts += vr.TotalFound
					for _, vh := range vr.VHosts {
						terminal.PrintVHostFound(vr.IP, vh)
					}
				}

				// Print summary
				terminal.PrintVHostSummary(totalVHosts, len(vhostResults))

				// Save VHost data to file
				vhostFile := filepath.Join(outputPath, "vhosts.txt")
				s.saveVHostData(vhostFile, vhostResults)

				s.log(fmt.Sprintf("VHost discovery completed: %d vhosts found on %d IPs", totalVHosts, len(vhostResults)))
			}
		}
	}

	// Update scan result (we'll add IP resolution to types later if needed)
	_ = phaseStart
	_ = result

	s.sendStatusUpdate("IP Resolution", 3, 100, fmt.Sprintf("Resolved %d unique IPs", len(result.ResolvedIPs)))

	return result.ResolvedIPs, nil
}

// saveVHostData saves VHost results to a file
func (s *Scanner) saveVHostData(filename string, results []*vhost.VHostResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, result := range results {
		fmt.Fprintf(file, "IP: %s\n", result.IP)
		for _, vh := range result.VHosts {
			fmt.Fprintf(file, "  - %s\n", vh)
		}
		fmt.Fprintln(file)
	}

	return nil
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

// runURLDiscovery runs Phase 4: URL Discovery
func (s *Scanner) runURLDiscovery(outputPath string) ([]string, error) {
	phaseStart := time.Now()
	s.sendStatusUpdate("URL Discovery", 4, 0, "Discovering URLs with Katana and GAU...")

	liveURLsFile := filepath.Join(outputPath, "live_urls.txt")

	terminal.PrintSectionHeader("PHASE 4: URL DISCOVERY")

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

	// Print summary
	terminal.PrintURLDiscoverySummary(
		mergeResult.KatanaURLs,
		mergeResult.GAUURLs,
		mergeResult.TotalURLs,
	)

	s.log(fmt.Sprintf("URL Discovery completed: %d unique URLs found", mergeResult.TotalURLs))

	// Read all URLs
	allURLsFile := filepath.Join(outputPath, "all_urls.txt")
	urls, err := readLinesFromFile(allURLsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read URLs: %v", err)
	}

	_ = phaseStart

	s.sendStatusUpdate("URL Discovery", 4, 100, fmt.Sprintf("Discovered %d URLs", len(urls)))

	return urls, nil
}

// runPortScan runs Phase 5: Port Scanning
func (s *Scanner) runPortScan(outputPath string) error {
	s.sendStatusUpdate("Port Scanning", 5, 0, "Scanning for open ports...")
	terminal.PrintSectionHeader("PHASE 5: PORT SCANNING")

	ipsFile := filepath.Join(outputPath, "ips_only.txt")

	// Verify IPs file exists
	if _, err := os.Stat(ipsFile); os.IsNotExist(err) {
		s.log("Skipping port scan: no IPs file found")
		return nil
	}

	// Run Nmap scan (top 10 critical ports only)
	scanner := port.NewScanner(ipsFile, outputPath)
	result, err := scanner.Run(s.ctx)
	if err != nil {
		return err
	}

	if result.TotalHosts == 0 {
		s.log("Port scan completed: no results")
		return nil
	}

	// Enrich services with CVE lookups
	cveLookup := cve.NewLookup()
	servicesWithCVEs := 0

	for i := range result.Services {
		svc := &result.Services[i]

		// Skip if already has CVEs from Nmap scripts
		if len(svc.CVEs) > 0 {
			servicesWithCVEs++
			// Print CVEs found by Nmap
			for _, cveID := range svc.CVEs {
				terminal.PrintCVEFound(svc.IP, svc.Port, svc.Service, cveID, "UNKNOWN")
			}
			continue
		}

		// Try to find CVEs via API lookup
		if svc.Service != "" {
			cves, err := cveLookup.SearchByService(s.ctx, svc.Service, svc.Version)
			if err == nil && len(cves) > 0 {
				servicesWithCVEs++
				for _, cveInfo := range cves {
					svc.CVEs = append(svc.CVEs, cveInfo.ID)
					terminal.PrintCVEFound(svc.IP, svc.Port, svc.Service, cveInfo.ID, cveInfo.Severity)
				}
			}
		}
	}

	// Print summary
	terminal.PrintPortScanSummary(result.TotalHosts, result.OpenPorts, servicesWithCVEs)

	s.log(fmt.Sprintf("Port scan completed: %d open ports, %d services with CVEs",
		result.OpenPorts, servicesWithCVEs))

	s.sendStatusUpdate("Port Scanning", 5, 100, fmt.Sprintf("Found %d open ports", result.OpenPorts))

	return nil
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

// runPhase6DeepAnalysis runs comprehensive security analysis
func (s *Scanner) runPhase6DeepAnalysis(outputPath string, subdomains []string) error {
	scanStart := time.Now()
	s.sendStatusUpdate("Deep Security Analysis", 6, 0, "Running comprehensive security checks...")

	terminal.PrintSectionDivider()
	fmt.Println()
	terminal.PrintInfo("Starting Deep Security Analysis...")
	fmt.Println()

	// 1. Technology Fingerprinting
	terminal.PrintProgress("Fingerprinting technologies...")
	techResults := s.runTechnologyFingerprinting(subdomains)
	terminal.PrintInfo(fmt.Sprintf("Fingerprinted %d subdomains", len(techResults)))

	// 2. Security Headers Analysis
	terminal.PrintProgress("Analyzing security headers...")
	securityResults := s.runSecurityHeadersAnalysis(subdomains)
	poorSecurity := 0
	for _, analysis := range securityResults {
		if analysis.Grade == "D" || analysis.Grade == "F" {
			poorSecurity++
		}
	}
	if poorSecurity > 0 {
		terminal.PrintWarning(fmt.Sprintf("%d subdomains with poor security headers", poorSecurity))
	}

	// 3. TLS/SSL Analysis
	terminal.PrintProgress("Analyzing TLS/SSL configurations...")
	tlsResults := s.runTLSAnalysis(subdomains)
	tlsVulns := 0
	for _, analysis := range tlsResults {
		tlsVulns += len(analysis.Vulnerabilities)
	}
	if tlsVulns > 0 {
		terminal.PrintWarning(fmt.Sprintf("%d TLS/SSL vulnerabilities found", tlsVulns))
	}

	// 4. Subdomain Takeover Detection
	terminal.PrintProgress("Checking for subdomain takeover...")
	takeoverVulns := s.runTakeoverDetection(subdomains)
	if len(takeoverVulns) > 0 {
		terminal.PrintWarning(fmt.Sprintf("Found %d subdomain takeover vulnerabilities", len(takeoverVulns)))
		for _, vuln := range takeover.GetCriticalVulnerabilities(takeoverVulns) {
			terminal.PrintAlert(fmt.Sprintf("CRITICAL: %s → %s (%s)", vuln.Subdomain, vuln.Service, vuln.Evidence))
		}
	}

	// 5. Cloud Asset Discovery
	terminal.PrintProgress("Discovering cloud assets...")
	cloudAssets := s.runCloudDiscovery()
	publicCount := 0
	writableCount := 0
	for _, asset := range cloudAssets {
		if asset.Status == "public" {
			publicCount++
		}
		if asset.IsWritable {
			writableCount++
			terminal.PrintAlert(fmt.Sprintf("CRITICAL: %s is WRITABLE!", asset.URL))
		}
	}
	if len(cloudAssets) > 0 {
		terminal.PrintInfo(fmt.Sprintf("Found %d cloud assets (%d public, %d writable)", len(cloudAssets), publicCount, writableCount))
	}

	// 6. API Intelligence
	terminal.PrintProgress("Discovering API endpoints...")
	apiResults := s.runAPIDiscovery(subdomains)
	totalAPI := 0
	for _, findings := range apiResults {
		totalAPI += len(findings)
	}
	if totalAPI > 0 {
		terminal.PrintInfo(fmt.Sprintf("Found %d API findings", totalAPI))
	}

	// 7. CORS Misconfiguration Detection
	terminal.PrintProgress("Testing CORS configurations...")
	corsResults := s.runCORSDetection(subdomains)
	totalCORS := 0
	for _, issues := range corsResults {
		for _, issue := range issues {
			totalCORS++
			if issue.Severity == "critical" {
				terminal.PrintAlert(fmt.Sprintf("CORS CRITICAL: %s - %s", issue.Subdomain, issue.Description))
			}
		}
	}
	if totalCORS > 0 {
		terminal.PrintWarning(fmt.Sprintf("Found %d CORS misconfigurations", totalCORS))
	}

	// 8. JS Secrets Scanning
	terminal.PrintProgress("Scanning JavaScript files for secrets...")
	secretResults := s.runSecretsScanning(subdomains)
	totalSecrets := 0
	criticalSecrets := 0
	for _, findings := range secretResults {
		for _, finding := range findings {
			totalSecrets++
			if finding.Severity == "critical" {
				criticalSecrets++
			}
		}
	}
	if totalSecrets > 0 {
		terminal.PrintWarning(fmt.Sprintf("Found %d secrets (%d critical)", totalSecrets, criticalSecrets))
	}

	// Save results to files
	if outputPath != "" {
		s.saveDeepAnalysisResults(outputPath, secretResults, takeoverVulns, cloudAssets)
	}

	fmt.Println()
	terminal.PrintSectionDivider()
	terminal.PrintSuccess(fmt.Sprintf("Deep Security Analysis completed in %s", time.Since(scanStart)))
	terminal.PrintSectionDivider()
	fmt.Println()

	s.sendStatusUpdate("Deep Security Analysis", 6, 100, "Security analysis complete")

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
	analyzer := tls.NewAnalyzer(10)
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
	checker := takeover.NewChecker(10)
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
	scanner := cloud.NewScanner(s.Config.Domain, 10)
	return scanner.ScanAll(s.ctx)
}

// runAPIDiscovery performs API intelligence discovery
func (s *Scanner) runAPIDiscovery(subdomains []string) map[string][]api.Finding {
	scanner := api.NewScanner(10)
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
	checker := cors.NewChecker(10)
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
	scanner := secrets.NewScanner(10)
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

// sendStatusUpdate sends scan status updates to web UI
func (s *Scanner) sendStatusUpdate(phase string, phaseNumber int, progress float64, message string) {
	if s.webUIServer == nil {
		return
	}

	elapsed := time.Since(s.startTime)
	minutes := int(elapsed.Minutes())
	seconds := int(elapsed.Seconds()) % 60

	status := webui.StatusUpdate{
		Phase:       phase,
		PhaseNumber: phaseNumber,
		Progress:    progress,
		Message:     message,
		ElapsedTime: fmt.Sprintf("%dm %ds", minutes, seconds),
	}

	s.webUIServer.SendUpdate("status", status)
}

// sendSubdomainUpdate sends new subdomain discovery to web UI
func (s *Scanner) sendSubdomainUpdate(subdomain, ipAddress, status string) {
	if s.webUIServer == nil {
		return
	}

	update := webui.SubdomainUpdate{
		Subdomain: subdomain,
		IPAddress: ipAddress,
		Status:    status,
	}

	s.webUIServer.SendUpdate("subdomain", update)
}

// sendVulnerabilityUpdate sends new vulnerability finding to web UI
func (s *Scanner) sendVulnerabilityUpdate(vuln webui.VulnerabilityUpdate) {
	if s.webUIServer == nil {
		return
	}

	s.webUIServer.SendUpdate("vulnerability", vuln)
}

// sendStatsUpdate sends overall statistics to web UI
func (s *Scanner) sendStatsUpdate(stats webui.StatsUpdate) {
	if s.webUIServer == nil {
		return
	}

	s.webUIServer.SendUpdate("stats", stats)
}
