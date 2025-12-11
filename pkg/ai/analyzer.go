package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourusername/pinakastra/pkg/api"
	"github.com/yourusername/pinakastra/pkg/cloud"
	"github.com/yourusername/pinakastra/pkg/cors"
	"github.com/yourusername/pinakastra/pkg/fingerprint"
	"github.com/yourusername/pinakastra/pkg/nuclei"
	"github.com/yourusername/pinakastra/pkg/secrets"
	"github.com/yourusername/pinakastra/pkg/security"
	"github.com/yourusername/pinakastra/pkg/takeover"
	"github.com/yourusername/pinakastra/pkg/tls"
)

// Analyzer is AI System 1 - Strategic analyzer that correlates findings
type Analyzer struct {
	context            context.Context
	subdomains         []string
	technologies       map[string][]fingerprint.Technology
	securityHeaders    map[string]*security.Analysis
	tlsAnalysis        map[string]*tls.Analysis
	takeoverVulns      []takeover.Vulnerability
	cloudAssets        []cloud.Asset
	apiFindings        map[string][]api.Finding
	corsIssues         map[string][]cors.Issue
	secretsFound       map[string][]secrets.Finding
	nucleiVulns        []nuclei.Vulnerability
}

// AnalysisResult contains the AI correlation results
type AnalysisResult struct {
	AttackChains       []AttackChain            `json:"attack_chains"`
	CriticalPaths      []ExploitationPath       `json:"critical_paths"`
	VulnerabilityMap   map[string][]VulnContext `json:"vulnerability_map"`
	HighValueTargets   []Target                 `json:"high_value_targets"`
	CorrelationScore   float64                  `json:"correlation_score"`
	TotalFindings      int                      `json:"total_findings"`
	ExploitableSurface int                      `json:"exploitable_surface"`
	AnalysisTimestamp  time.Time                `json:"timestamp"`
}

// AttackChain represents a sequence of vulnerabilities that can be chained
type AttackChain struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Severity    string       `json:"severity"`
	Steps       []ChainStep  `json:"steps"`
	FinalImpact string       `json:"final_impact"`
	Complexity  string       `json:"complexity"`
	Confidence  float64      `json:"confidence"`
}

// ChainStep represents one step in an attack chain
type ChainStep struct {
	StepNumber  int      `json:"step_number"`
	VulnType    string   `json:"vuln_type"`
	Target      string   `json:"target"` // Subdomain
	URL         string   `json:"url"` // Full affected URL
	Endpoint    string   `json:"endpoint"` // Specific endpoint/parameter
	Description string   `json:"description"`
	RequiredFor string   `json:"required_for"` // What this enables
}

// ExploitationPath represents a direct path to compromise
type ExploitationPath struct {
	PathID      string   `json:"path_id"`
	Severity    string   `json:"severity"`
	Target      string   `json:"target"`
	URL         string   `json:"url"`
	Endpoint    string   `json:"endpoint"`
	VulnType    string   `json:"vuln_type"`
	Impact      string   `json:"impact"`
	Difficulty  string   `json:"difficulty"`
	Prerequisites []string `json:"prerequisites,omitempty"`
}

// VulnContext provides context about a vulnerability
type VulnContext struct {
	Type           string   `json:"type"`
	Subdomain      string   `json:"subdomain"`
	URL            string   `json:"url"`
	Endpoint       string   `json:"endpoint"`
	Severity       string   `json:"severity"`
	Technologies   []string `json:"technologies"`
	RelatedSecrets []string `json:"related_secrets,omitempty"`
	Exploitable    bool     `json:"exploitable"`
}

// Target represents a high-value target
type Target struct {
	Subdomain     string   `json:"subdomain"`
	URLs          []string `json:"urls"`
	Technologies  []string `json:"technologies"`
	Vulnerabilities int    `json:"vulnerabilities"`
	Secrets       int      `json:"secrets"`
	RiskScore     float64  `json:"risk_score"`
	Reasoning     string   `json:"reasoning"`
}

// NewAnalyzer creates a new AI analyzer
func NewAnalyzer(ctx context.Context) *Analyzer {
	return &Analyzer{
		context:         ctx,
		technologies:    make(map[string][]fingerprint.Technology),
		securityHeaders: make(map[string]*security.Analysis),
		tlsAnalysis:     make(map[string]*tls.Analysis),
		apiFindings:     make(map[string][]api.Finding),
		corsIssues:      make(map[string][]cors.Issue),
		secretsFound:    make(map[string][]secrets.Finding),
	}
}

// LoadFindings loads all reconnaissance findings into the analyzer
func (a *Analyzer) LoadFindings(
	subdomains []string,
	technologies map[string][]fingerprint.Technology,
	securityHeaders map[string]*security.Analysis,
	tlsAnalysis map[string]*tls.Analysis,
	takeoverVulns []takeover.Vulnerability,
	cloudAssets []cloud.Asset,
	apiFindings map[string][]api.Finding,
	corsIssues map[string][]cors.Issue,
	secretsFound map[string][]secrets.Finding,
	nucleiVulns []nuclei.Vulnerability,
) {
	a.subdomains = subdomains
	a.technologies = technologies
	a.securityHeaders = securityHeaders
	a.tlsAnalysis = tlsAnalysis
	a.takeoverVulns = takeoverVulns
	a.cloudAssets = cloudAssets
	a.apiFindings = apiFindings
	a.corsIssues = corsIssues
	a.secretsFound = secretsFound
	a.nucleiVulns = nucleiVulns
}

// Analyze performs deep AI correlation analysis
func (a *Analyzer) Analyze() *AnalysisResult {
	result := &AnalysisResult{
		AnalysisTimestamp: time.Now(),
		VulnerabilityMap:  make(map[string][]VulnContext),
	}

	// Count total findings
	result.TotalFindings = a.countTotalFindings()

	// Build vulnerability context map
	a.buildVulnerabilityMap(result)

	// Identify attack chains
	result.AttackChains = a.identifyAttackChains()

	// Identify critical exploitation paths
	result.CriticalPaths = a.identifyCriticalPaths()

	// Identify high-value targets
	result.HighValueTargets = a.identifyHighValueTargets()

	// Calculate correlation score
	result.CorrelationScore = a.calculateCorrelationScore(result)

	// Count exploitable surface
	result.ExploitableSurface = len(result.CriticalPaths) + len(result.AttackChains)

	return result
}

// countTotalFindings counts all findings across all phases
func (a *Analyzer) countTotalFindings() int {
	count := 0
	count += len(a.nucleiVulns)
	count += len(a.takeoverVulns)
	count += len(a.cloudAssets)

	for _, findings := range a.apiFindings {
		count += len(findings)
	}
	for _, issues := range a.corsIssues {
		count += len(issues)
	}
	for _, secrets := range a.secretsFound {
		count += len(secrets)
	}

	return count
}

// buildVulnerabilityMap creates context for each vulnerability
func (a *Analyzer) buildVulnerabilityMap(result *AnalysisResult) {
	// Map Nuclei vulnerabilities
	for _, vuln := range a.nucleiVulns {
		ctx := VulnContext{
			Type:      vuln.Type,
			Subdomain: extractSubdomain(vuln.Host),
			URL:       vuln.MatchedAt,
			Endpoint:  extractEndpoint(vuln.MatchedAt),
			Severity:  vuln.Severity,
			Exploitable: true,
		}

		// Add technology context
		if techs, ok := a.technologies[ctx.Subdomain]; ok {
			for _, tech := range techs {
				ctx.Technologies = append(ctx.Technologies, tech.Name)
			}
		}

		result.VulnerabilityMap[ctx.Subdomain] = append(result.VulnerabilityMap[ctx.Subdomain], ctx)
	}

	// Map API findings
	for subdomain, findings := range a.apiFindings {
		for _, finding := range findings {
			ctx := VulnContext{
				Type:      finding.Type,
				Subdomain: subdomain,
				URL:       finding.URL,
				Endpoint:  extractEndpoint(finding.URL),
				Severity:  finding.Severity,
				Exploitable: finding.Severity == "critical" || finding.Severity == "high",
			}
			result.VulnerabilityMap[subdomain] = append(result.VulnerabilityMap[subdomain], ctx)
		}
	}

	// Map CORS issues
	for subdomain, issues := range a.corsIssues {
		for _, issue := range issues {
			ctx := VulnContext{
				Type:      "cors_misconfiguration",
				Subdomain: subdomain,
				URL:       fmt.Sprintf("https://%s", subdomain),
				Endpoint:  "/",
				Severity:  issue.Severity,
				Exploitable: issue.Severity == "critical" || issue.Severity == "high",
			}
			result.VulnerabilityMap[subdomain] = append(result.VulnerabilityMap[subdomain], ctx)
		}
	}

	// Map secrets with related URLs
	for subdomain, secrets := range a.secretsFound {
		for _, secret := range secrets {
			ctx := VulnContext{
				Type:      "exposed_secret",
				Subdomain: subdomain,
				URL:       secret.Source,
				Endpoint:  secret.Source,
				Severity:  secret.Severity,
				RelatedSecrets: []string{secret.Type},
				Exploitable: true,
			}
			result.VulnerabilityMap[subdomain] = append(result.VulnerabilityMap[subdomain], ctx)
		}
	}
}

// identifyAttackChains identifies complex attack chains
func (a *Analyzer) identifyAttackChains() []AttackChain {
	var chains []AttackChain
	chainID := 1

	// Chain 1: Cloud Infrastructure Compromise
	// Pattern: Exposed cloud credentials + Cloud bucket found = Infrastructure takeover
	for subdomain, secrets := range a.secretsFound {
		for _, secret := range secrets {
			if strings.Contains(strings.ToLower(secret.Type), "aws") ||
			   strings.Contains(strings.ToLower(secret.Type), "gcp") ||
			   strings.Contains(strings.ToLower(secret.Type), "azure") {

				// Check if we found corresponding cloud buckets
				var relatedBuckets []cloud.Asset
				for _, asset := range a.cloudAssets {
					if strings.Contains(asset.Bucket, subdomain) {
						relatedBuckets = append(relatedBuckets, asset)
					}
				}

				if len(relatedBuckets) > 0 {
					chain := AttackChain{
						ID:       fmt.Sprintf("CHAIN-%03d", chainID),
						Name:     "Cloud Infrastructure Compromise",
						Severity: "critical",
						Complexity: "low",
						Confidence: 0.95,
						FinalImpact: "Full cloud infrastructure access, data exfiltration, resource manipulation",
						Steps: []ChainStep{
							{
								StepNumber: 1,
								VulnType:   "exposed_credentials",
								Target:     subdomain,
								URL:        secret.Source,
								Endpoint:   secret.Source,
								Description: fmt.Sprintf("Exposed %s credentials found in JavaScript file", secret.Type),
								RequiredFor: "Cloud API authentication",
							},
							{
								StepNumber: 2,
								VulnType:   "cloud_bucket_writable",
								Target:     subdomain,
								URL:        relatedBuckets[0].URL,
								Endpoint:   relatedBuckets[0].Bucket,
								Description: fmt.Sprintf("%s bucket accessible with write permissions", relatedBuckets[0].Provider),
								RequiredFor: "Data exfiltration and manipulation",
							},
						},
					}
					chains = append(chains, chain)
					chainID++
				}
			}
		}
	}

	// Chain 2: Authentication Bypass → Privilege Escalation
	// Pattern: GraphQL introspection + IDOR/API vuln = Admin access
	for subdomain, apiFindings := range a.apiFindings {
		var hasGraphQL, hasIDOR bool
		var graphqlURL, idorURL string

		for _, finding := range apiFindings {
			if finding.Type == "graphql" && finding.Issue == "introspection_enabled" {
				hasGraphQL = true
				graphqlURL = finding.URL
			}
		}

		// Check for IDOR in nuclei findings
		for _, vuln := range a.nucleiVulns {
			if extractSubdomain(vuln.Host) == subdomain {
				if strings.Contains(strings.ToLower(vuln.Name), "idor") ||
				   strings.Contains(strings.ToLower(vuln.Name), "access control") {
					hasIDOR = true
					idorURL = vuln.MatchedAt
				}
			}
		}

		if hasGraphQL && hasIDOR {
			chain := AttackChain{
				ID:       fmt.Sprintf("CHAIN-%03d", chainID),
				Name:     "Authentication Bypass to Privilege Escalation",
				Severity: "high",
				Complexity: "medium",
				Confidence: 0.85,
				FinalImpact: "Administrative access to application, full data access",
				Steps: []ChainStep{
					{
						StepNumber: 1,
						VulnType:   "graphql_introspection",
						Target:     subdomain,
						URL:        graphqlURL,
						Endpoint:   extractEndpoint(graphqlURL),
						Description: "GraphQL introspection reveals sensitive queries and mutations",
						RequiredFor: "Understanding API structure and privilege escalation endpoints",
					},
					{
						StepNumber: 2,
						VulnType:   "idor",
						Target:     subdomain,
						URL:        idorURL,
						Endpoint:   extractEndpoint(idorURL),
						Description: "IDOR vulnerability allows access to other users' data",
						RequiredFor: "Escalating privileges to administrator",
					},
				},
			}
			chains = append(chains, chain)
			chainID++
		}
	}

	// Chain 3: Subdomain Takeover → Session Hijacking
	// Pattern: Subdomain takeover + CORS misconfiguration = Session theft
	for _, takeover := range a.takeoverVulns {
		if corsIssues, ok := a.corsIssues[takeover.Subdomain]; ok {
			for _, corsIssue := range corsIssues {
				if corsIssue.Severity == "critical" || corsIssue.Severity == "high" {
					chain := AttackChain{
						ID:       fmt.Sprintf("CHAIN-%03d", chainID),
						Name:     "Subdomain Takeover to Session Hijacking",
						Severity: "high",
						Complexity: "medium",
						Confidence: 0.80,
						FinalImpact: "Full session hijacking, user account takeover",
						Steps: []ChainStep{
							{
								StepNumber: 1,
								VulnType:   "subdomain_takeover",
								Target:     takeover.Subdomain,
								URL:        fmt.Sprintf("https://%s", takeover.Subdomain),
								Endpoint:   "/",
								Description: fmt.Sprintf("Subdomain vulnerable to takeover via %s", takeover.Service),
								RequiredFor: "Hosting malicious content on trusted domain",
							},
							{
								StepNumber: 2,
								VulnType:   "cors_misconfiguration",
								Target:     takeover.Subdomain,
								URL:        fmt.Sprintf("https://%s", takeover.Subdomain),
								Endpoint:   "/",
								Description: "CORS allows arbitrary origins with credentials",
								RequiredFor: "Stealing session cookies and tokens",
							},
						},
					}
					chains = append(chains, chain)
					chainID++
					break
				}
			}
		}
	}

	// Chain 4: XSS → CSRF → Account Takeover
	// Pattern: XSS vulnerability + Missing CSRF protection = Account takeover
	for subdomain, vulns := range a.vulnerabilityMap() {
		var hasXSS, hasCSRF bool
		var xssURL, csrfURL string

		for _, vuln := range vulns {
			if strings.Contains(strings.ToLower(vuln.Type), "xss") {
				hasXSS = true
				xssURL = vuln.URL
			}
		}

		// Check security headers for CSRF protection
		if headers, ok := a.securityHeaders[subdomain]; ok {
			if !headers.HasCSRFProtection {
				hasCSRF = true
				csrfURL = fmt.Sprintf("https://%s", subdomain)
			}
		}

		if hasXSS && hasCSRF {
			chain := AttackChain{
				ID:       fmt.Sprintf("CHAIN-%03d", chainID),
				Name:     "XSS to CSRF to Account Takeover",
				Severity: "medium",
				Complexity: "medium",
				Confidence: 0.75,
				FinalImpact: "Account takeover, unauthorized actions on behalf of users",
				Steps: []ChainStep{
					{
						StepNumber: 1,
						VulnType:   "xss",
						Target:     subdomain,
						URL:        xssURL,
						Endpoint:   extractEndpoint(xssURL),
						Description: "XSS vulnerability allows JavaScript injection",
						RequiredFor: "Executing CSRF attacks via injected scripts",
					},
					{
						StepNumber: 2,
						VulnType:   "csrf",
						Target:     subdomain,
						URL:        csrfURL,
						Endpoint:   "/",
						Description: "Missing CSRF tokens on state-changing operations",
						RequiredFor: "Performing unauthorized actions",
					},
				},
			}
			chains = append(chains, chain)
			chainID++
		}
	}

	return chains
}

// identifyCriticalPaths identifies direct exploitation paths
func (a *Analyzer) identifyCriticalPaths() []ExploitationPath {
	var paths []ExploitationPath
	pathID := 1

	// Critical path: SQL Injection
	for _, vuln := range a.nucleiVulns {
		if strings.Contains(strings.ToLower(vuln.Name), "sql") {
			path := ExploitationPath{
				PathID:     fmt.Sprintf("PATH-%03d", pathID),
				Severity:   vuln.Severity,
				Target:     extractSubdomain(vuln.Host),
				URL:        vuln.MatchedAt,
				Endpoint:   extractEndpoint(vuln.MatchedAt),
				VulnType:   "sql_injection",
				Impact:     "Database access, data exfiltration, potential RCE",
				Difficulty: "low",
			}
			paths = append(paths, path)
			pathID++
		}
	}

	// Critical path: RCE vulnerabilities
	for _, vuln := range a.nucleiVulns {
		if strings.Contains(strings.ToLower(vuln.Name), "rce") ||
		   strings.Contains(strings.ToLower(vuln.Name), "remote code") ||
		   strings.Contains(strings.ToLower(vuln.Name), "command injection") {
			path := ExploitationPath{
				PathID:     fmt.Sprintf("PATH-%03d", pathID),
				Severity:   "critical",
				Target:     extractSubdomain(vuln.Host),
				URL:        vuln.MatchedAt,
				Endpoint:   extractEndpoint(vuln.MatchedAt),
				VulnType:   "rce",
				Impact:     "Complete server compromise, full system access",
				Difficulty: "low",
			}
			paths = append(paths, path)
			pathID++
		}
	}

	// Critical path: Exposed admin panels
	for subdomain, findings := range a.apiFindings {
		for _, finding := range findings {
			if strings.Contains(strings.ToLower(finding.URL), "admin") {
				path := ExploitationPath{
					PathID:     fmt.Sprintf("PATH-%03d", pathID),
					Severity:   finding.Severity,
					Target:     subdomain,
					URL:        finding.URL,
					Endpoint:   extractEndpoint(finding.URL),
					VulnType:   "exposed_admin_panel",
					Impact:     "Administrative access if default credentials work",
					Difficulty: "low",
					Prerequisites: []string{"Default credentials", "Authentication bypass"},
				}
				paths = append(paths, path)
				pathID++
			}
		}
	}

	return paths
}

// identifyHighValueTargets identifies subdomains with highest risk
func (a *Analyzer) identifyHighValueTargets() []Target {
	targetMap := make(map[string]*Target)

	// Calculate risk scores for each subdomain
	for _, subdomain := range a.subdomains {
		target := &Target{
			Subdomain: subdomain,
			URLs:      []string{fmt.Sprintf("https://%s", subdomain)},
		}

		// Count vulnerabilities
		if vulns, ok := a.vulnerabilityMap()[subdomain]; ok {
			target.Vulnerabilities = len(vulns)
		}

		// Count secrets
		if secrets, ok := a.secretsFound[subdomain]; ok {
			target.Secrets = len(secrets)
		}

		// Add technologies
		if techs, ok := a.technologies[subdomain]; ok {
			for _, tech := range techs {
				target.Technologies = append(target.Technologies, tech.Name)
			}
		}

		// Calculate risk score
		target.RiskScore = a.calculateRiskScore(target)

		// Add reasoning
		target.Reasoning = a.generateReasoning(target)

		if target.RiskScore > 50.0 {
			targetMap[subdomain] = target
		}
	}

	// Convert to slice
	var targets []Target
	for _, target := range targetMap {
		targets = append(targets, *target)
	}

	return targets
}

// Helper functions

func (a *Analyzer) vulnerabilityMap() map[string][]VulnContext {
	result := make(map[string][]VulnContext)

	for _, vuln := range a.nucleiVulns {
		subdomain := extractSubdomain(vuln.Host)
		ctx := VulnContext{
			Type:     vuln.Type,
			Subdomain: subdomain,
			URL:      vuln.MatchedAt,
			Endpoint: extractEndpoint(vuln.MatchedAt),
			Severity: vuln.Severity,
		}
		result[subdomain] = append(result[subdomain], ctx)
	}

	return result
}

func (a *Analyzer) calculateCorrelationScore(result *AnalysisResult) float64 {
	if result.TotalFindings == 0 {
		return 0.0
	}

	// Score based on attack chains found
	chainScore := float64(len(result.AttackChains)) * 10.0
	pathScore := float64(len(result.CriticalPaths)) * 5.0
	targetScore := float64(len(result.HighValueTargets)) * 3.0

	totalScore := chainScore + pathScore + targetScore
	maxScore := float64(result.TotalFindings) * 2.0

	if maxScore == 0 {
		return 0.0
	}

	score := (totalScore / maxScore) * 100.0
	if score > 100.0 {
		score = 100.0
	}

	return score
}

func (a *Analyzer) calculateRiskScore(target *Target) float64 {
	score := 0.0

	// Vulnerabilities weight
	score += float64(target.Vulnerabilities) * 10.0

	// Secrets weight (higher impact)
	score += float64(target.Secrets) * 15.0

	// Technology stack complexity
	score += float64(len(target.Technologies)) * 2.0

	return score
}

func (a *Analyzer) generateReasoning(target *Target) string {
	reasons := []string{}

	if target.Vulnerabilities > 5 {
		reasons = append(reasons, fmt.Sprintf("%d vulnerabilities detected", target.Vulnerabilities))
	}
	if target.Secrets > 0 {
		reasons = append(reasons, fmt.Sprintf("%d exposed secrets", target.Secrets))
	}
	if len(target.Technologies) > 10 {
		reasons = append(reasons, "complex technology stack")
	}

	if len(reasons) == 0 {
		return "Moderate risk"
	}

	return strings.Join(reasons, ", ")
}

func extractSubdomain(host string) string {
	// Remove protocol
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")

	// Remove port
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Remove path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	return host
}

func extractEndpoint(url string) string {
	// Remove protocol and host
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Find first slash
	if idx := strings.Index(url, "/"); idx != -1 {
		return url[idx:]
	}

	return "/"
}
