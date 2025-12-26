package intelligence

import (
	"context"
	"fmt"
	"strings"

	"github.com/who0xac/pinakastra/pkg/ollama"
)

// SecurityAnalyzer analyzes security findings using AI
type SecurityAnalyzer struct {
	ollamaClient *ollama.Client
	deepMode     bool
}

// SecurityFinding represents a security issue found during deep analysis
type SecurityFinding struct {
	Type        string   // "header", "tls", "cors", "secret", "takeover", "cloud", "api"
	Subdomain   string
	Severity    string
	Description string
	Details     map[string]interface{}
}

// SecurityAnalysisResult contains AI analysis of security findings
type SecurityAnalysisResult struct {
	Finding        SecurityFinding
	RiskLevel      string   // CRITICAL, HIGH, MODERATE, LOW
	Exploitability string   // How easy to exploit
	CVEs           []string // Related CVE identifiers
	AttackChain    string   // For deep mode: how to chain with other vulns
	POC            string   // For deep mode: proof of concept
}

// NewSecurityAnalyzer creates a new security analyzer
func NewSecurityAnalyzer(model string, deepMode bool) *SecurityAnalyzer {
	return &SecurityAnalyzer{
		ollamaClient: ollama.NewClient(model),
		deepMode:     deepMode,
	}
}

// IsAvailable checks if Ollama is running
func (a *SecurityAnalyzer) IsAvailable(ctx context.Context) bool {
	return a.ollamaClient.IsAvailable(ctx)
}

// AnalyzeFinding analyzes a single security finding
func (a *SecurityAnalyzer) AnalyzeFinding(ctx context.Context, finding SecurityFinding) (*SecurityAnalysisResult, error) {
	var prompt string

	if a.deepMode {
		// Deep analysis mode
		prompt = a.buildDeepAnalysisPrompt(finding)
	} else {
		// Basic analysis mode
		prompt = a.buildBasicAnalysisPrompt(finding)
	}

	response, err := a.ollamaClient.Chat(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %v", err)
	}

	return a.parseAnalysisResponse(response, finding), nil
}

// buildBasicAnalysisPrompt creates prompt for basic AI analysis
func (a *SecurityAnalyzer) buildBasicAnalysisPrompt(finding SecurityFinding) string {
	return fmt.Sprintf(`Analyze this security finding:

Type: %s
Subdomain: %s
Severity: %s
Description: %s

Provide a concise security analysis:
1. Risk Level (CRITICAL/HIGH/MODERATE/LOW)
2. Exploitability (How easy is it to exploit?)
3. Related CVE identifiers (if any)

Format your response as:
RISK: [level]
EXPLOITABILITY: [description]
CVES: [CVE-XXXX-XXXXX, CVE-YYYY-YYYYY] (or "None" if no related CVEs)`,
		finding.Type,
		finding.Subdomain,
		finding.Severity,
		finding.Description)
}

// buildDeepAnalysisPrompt creates prompt for deep AI analysis
func (a *SecurityAnalyzer) buildDeepAnalysisPrompt(finding SecurityFinding) string {
	return fmt.Sprintf(`Perform deep security analysis on this finding:

Type: %s
Subdomain: %s
Severity: %s
Description: %s

Provide comprehensive analysis:
1. Risk Level (CRITICAL/HIGH/MODERATE/LOW)
2. Detailed Exploitability Assessment
3. Related CVE identifiers (if any)
4. Attack Chain (How this can be combined with other vulnerabilities)
5. Proof of Concept (Basic exploit steps or code)

Format your response as:
RISK: [level]
EXPLOITABILITY: [detailed description]
CVES: [CVE-XXXX-XXXXX, CVE-YYYY-YYYYY] (or "None" if no related CVEs)
ATTACK_CHAIN: [how to chain with other vulnerabilities]
POC: [proof of concept steps or code]`,
		finding.Type,
		finding.Subdomain,
		finding.Severity,
		finding.Description)
}

// parseAnalysisResponse parses AI response into structured result
func (a *SecurityAnalyzer) parseAnalysisResponse(response string, finding SecurityFinding) *SecurityAnalysisResult {
	result := &SecurityAnalysisResult{
		Finding:        finding,
		RiskLevel:      "UNKNOWN",
		Exploitability: "",
		CVEs:           []string{},
		AttackChain:    "",
		POC:            "",
	}

	lines := strings.Split(response, "\n")
	var currentSection string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse sections
		if strings.HasPrefix(line, "RISK:") {
			result.RiskLevel = strings.TrimSpace(strings.TrimPrefix(line, "RISK:"))
		} else if strings.HasPrefix(line, "EXPLOITABILITY:") {
			result.Exploitability = strings.TrimSpace(strings.TrimPrefix(line, "EXPLOITABILITY:"))
			currentSection = "exploitability"
		} else if strings.HasPrefix(line, "CVES:") {
			cvesStr := strings.TrimSpace(strings.TrimPrefix(line, "CVES:"))
			if cvesStr != "None" && cvesStr != "" {
				// Parse CVE identifiers
				cves := strings.Split(cvesStr, ",")
				for _, cve := range cves {
					cve = strings.TrimSpace(cve)
					if cve != "" {
						result.CVEs = append(result.CVEs, cve)
					}
				}
			}
			currentSection = ""
		} else if strings.HasPrefix(line, "ATTACK_CHAIN:") {
			result.AttackChain = strings.TrimSpace(strings.TrimPrefix(line, "ATTACK_CHAIN:"))
			currentSection = "attack_chain"
		} else if strings.HasPrefix(line, "POC:") {
			result.POC = strings.TrimSpace(strings.TrimPrefix(line, "POC:"))
			currentSection = "poc"
		} else {
			// Continue previous section
			switch currentSection {
			case "exploitability":
				result.Exploitability += " " + line
			case "attack_chain":
				result.AttackChain += " " + line
			case "poc":
				result.POC += "\n" + line
			}
		}
	}

	return result
}

// AnalyzeMultipleFindings analyzes multiple findings and provides overall assessment
func (a *SecurityAnalyzer) AnalyzeMultipleFindings(ctx context.Context, findings []SecurityFinding) ([]SecurityAnalysisResult, error) {
	results := []SecurityAnalysisResult{}

	for _, finding := range findings {
		result, err := a.AnalyzeFinding(ctx, finding)
		if err != nil {
			// Log error but continue with other findings
			continue
		}
		results = append(results, *result)
	}

	return results, nil
}
