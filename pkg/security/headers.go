package security

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HeaderAnalysis represents security header analysis results
type HeaderAnalysis struct {
	Subdomain            string            `json:"subdomain"`
	Score                int               `json:"score"` // 0-10
	Grade                string            `json:"grade"` // A+, A, B, C, D, F
	MissingHeaders       []string          `json:"missing_headers"`
	PresentHeaders       map[string]string `json:"present_headers"`
	Warnings             []string          `json:"warnings"`
	CriticalIssues       []string          `json:"critical_issues"`
	Recommendations      []string          `json:"recommendations"`
}

// Analyzer performs security header analysis
type Analyzer struct {
	client  *http.Client
	timeout time.Duration
}

// NewAnalyzer creates a new security header analyzer
func NewAnalyzer(timeout int) *Analyzer {
	return &Analyzer{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		timeout: time.Duration(timeout) * time.Second,
	}
}

// AnalyzeHeaders analyzes security headers for a subdomain
func (a *Analyzer) AnalyzeHeaders(ctx context.Context, subdomain string) *HeaderAnalysis {
	analysis := &HeaderAnalysis{
		Subdomain:      subdomain,
		PresentHeaders: make(map[string]string),
		Score:          10, // Start with perfect score, deduct points
	}

	// Try HTTPS first, then HTTP
	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	var resp *http.Response
	var err error
	var req *http.Request

	for _, url := range urls {
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err = a.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode < 500 {
			break // Got valid response
		}
	}

	if resp == nil {
		analysis.Score = 0
		analysis.Grade = "F"
		analysis.CriticalIssues = append(analysis.CriticalIssues, "Unable to connect to server")
		return analysis
	}

	// Check critical security headers
	a.checkCSP(resp, analysis)
	a.checkHSTS(resp, analysis)
	a.checkXFrameOptions(resp, analysis)
	a.checkXContentTypeOptions(resp, analysis)
	a.checkReferrerPolicy(resp, analysis)
	a.checkPermissionsPolicy(resp, analysis)
	a.checkXXSSProtection(resp, analysis)
	a.checkCORS(resp, analysis)

	// Check for information disclosure
	a.checkInformationDisclosure(resp, analysis)

	// Calculate grade based on score
	analysis.Grade = calculateGrade(analysis.Score)

	return analysis
}

// checkCSP checks Content-Security-Policy header
func (a *Analyzer) checkCSP(resp *http.Response, analysis *HeaderAnalysis) {
	csp := resp.Header.Get("Content-Security-Policy")
	cspRO := resp.Header.Get("Content-Security-Policy-Report-Only")

	if csp == "" && cspRO == "" {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Content-Security-Policy")
		analysis.CriticalIssues = append(analysis.CriticalIssues, "Missing Content-Security-Policy (CSP)")
		analysis.Recommendations = append(analysis.Recommendations, "Implement CSP to prevent XSS attacks")
		analysis.Score -= 2
	} else if csp != "" {
		analysis.PresentHeaders["Content-Security-Policy"] = csp

		// Check for unsafe directives
		if strings.Contains(csp, "unsafe-inline") {
			analysis.Warnings = append(analysis.Warnings, "CSP allows 'unsafe-inline' (reduces XSS protection)")
			analysis.Score -= 1
		}
		if strings.Contains(csp, "unsafe-eval") {
			analysis.Warnings = append(analysis.Warnings, "CSP allows 'unsafe-eval' (security risk)")
			analysis.Score -= 1
		}
		if strings.Contains(csp, "*") && !strings.Contains(csp, "data:*") {
			analysis.Warnings = append(analysis.Warnings, "CSP uses wildcard (*) - too permissive")
			analysis.Score -= 1
		}
	} else if cspRO != "" {
		analysis.PresentHeaders["Content-Security-Policy-Report-Only"] = cspRO
		analysis.Warnings = append(analysis.Warnings, "CSP is in Report-Only mode (not enforced)")
		analysis.Score -= 1
	}
}

// checkHSTS checks Strict-Transport-Security header
func (a *Analyzer) checkHSTS(resp *http.Response, analysis *HeaderAnalysis) {
	hsts := resp.Header.Get("Strict-Transport-Security")

	if hsts == "" {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Strict-Transport-Security")
		analysis.CriticalIssues = append(analysis.CriticalIssues, "Missing HSTS header")
		analysis.Recommendations = append(analysis.Recommendations, "Enable HSTS to prevent protocol downgrade attacks")
		analysis.Score -= 2
	} else {
		analysis.PresentHeaders["Strict-Transport-Security"] = hsts

		// Check max-age
		if !strings.Contains(hsts, "max-age") {
			analysis.Warnings = append(analysis.Warnings, "HSTS missing max-age directive")
			analysis.Score -= 1
		} else if strings.Contains(hsts, "max-age=0") {
			analysis.CriticalIssues = append(analysis.CriticalIssues, "HSTS max-age is 0 (disabled)")
			analysis.Score -= 1
		}

		// Check for includeSubDomains
		if !strings.Contains(hsts, "includeSubDomains") {
			analysis.Recommendations = append(analysis.Recommendations, "Consider adding 'includeSubDomains' to HSTS")
		}

		// Check for preload
		if strings.Contains(hsts, "preload") {
			// Bonus for preload
		}
	}
}

// checkXFrameOptions checks X-Frame-Options header
func (a *Analyzer) checkXFrameOptions(resp *http.Response, analysis *HeaderAnalysis) {
	xfo := resp.Header.Get("X-Frame-Options")

	if xfo == "" {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "X-Frame-Options")
		analysis.Warnings = append(analysis.Warnings, "Missing X-Frame-Options (clickjacking risk)")
		analysis.Recommendations = append(analysis.Recommendations, "Set X-Frame-Options to DENY or SAMEORIGIN")
		analysis.Score -= 1
	} else {
		analysis.PresentHeaders["X-Frame-Options"] = xfo

		xfoUpper := strings.ToUpper(xfo)
		if xfoUpper != "DENY" && xfoUpper != "SAMEORIGIN" {
			analysis.Warnings = append(analysis.Warnings, "X-Frame-Options has weak value")
			analysis.Score -= 1
		}
	}
}

// checkXContentTypeOptions checks X-Content-Type-Options header
func (a *Analyzer) checkXContentTypeOptions(resp *http.Response, analysis *HeaderAnalysis) {
	xcto := resp.Header.Get("X-Content-Type-Options")

	if xcto == "" {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "X-Content-Type-Options")
		analysis.Warnings = append(analysis.Warnings, "Missing X-Content-Type-Options (MIME sniffing risk)")
		analysis.Recommendations = append(analysis.Recommendations, "Set X-Content-Type-Options to 'nosniff'")
		analysis.Score -= 1
	} else {
		analysis.PresentHeaders["X-Content-Type-Options"] = xcto

		if strings.ToLower(xcto) != "nosniff" {
			analysis.Warnings = append(analysis.Warnings, "X-Content-Type-Options should be 'nosniff'")
		}
	}
}

// checkReferrerPolicy checks Referrer-Policy header
func (a *Analyzer) checkReferrerPolicy(resp *http.Response, analysis *HeaderAnalysis) {
	rp := resp.Header.Get("Referrer-Policy")

	if rp == "" {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Referrer-Policy")
		analysis.Recommendations = append(analysis.Recommendations, "Set Referrer-Policy to protect sensitive data in URLs")
		analysis.Score -= 0
	} else {
		analysis.PresentHeaders["Referrer-Policy"] = rp

		// Check for insecure policies
		rpLower := strings.ToLower(rp)
		if rpLower == "unsafe-url" || rpLower == "no-referrer-when-downgrade" {
			analysis.Warnings = append(analysis.Warnings, "Referrer-Policy is too permissive")
		}
	}
}

// checkPermissionsPolicy checks Permissions-Policy header
func (a *Analyzer) checkPermissionsPolicy(resp *http.Response, analysis *HeaderAnalysis) {
	pp := resp.Header.Get("Permissions-Policy")
	fpo := resp.Header.Get("Feature-Policy") // Deprecated but still check

	if pp == "" && fpo == "" {
		analysis.MissingHeaders = append(analysis.MissingHeaders, "Permissions-Policy")
		analysis.Recommendations = append(analysis.Recommendations, "Set Permissions-Policy to restrict browser features")
	} else if pp != "" {
		analysis.PresentHeaders["Permissions-Policy"] = pp
	} else if fpo != "" {
		analysis.PresentHeaders["Feature-Policy"] = fpo
		analysis.Warnings = append(analysis.Warnings, "Using deprecated Feature-Policy (use Permissions-Policy instead)")
	}
}

// checkXXSSProtection checks X-XSS-Protection header
func (a *Analyzer) checkXXSSProtection(resp *http.Response, analysis *HeaderAnalysis) {
	xxp := resp.Header.Get("X-XSS-Protection")

	if xxp != "" {
		analysis.PresentHeaders["X-XSS-Protection"] = xxp

		// X-XSS-Protection is deprecated and can cause vulnerabilities
		if xxp == "1; mode=block" {
			// This is OK (legacy but harmless)
		} else if xxp == "0" {
			analysis.Warnings = append(analysis.Warnings, "X-XSS-Protection is disabled")
		} else {
			analysis.Warnings = append(analysis.Warnings, "X-XSS-Protection has non-standard value")
		}
	}
}

// checkCORS checks CORS headers
func (a *Analyzer) checkCORS(resp *http.Response, analysis *HeaderAnalysis) {
	acao := resp.Header.Get("Access-Control-Allow-Origin")

	if acao != "" {
		analysis.PresentHeaders["Access-Control-Allow-Origin"] = acao

		if acao == "*" {
			analysis.CriticalIssues = append(analysis.CriticalIssues, "CORS allows all origins (*) - major security risk")
			analysis.Recommendations = append(analysis.Recommendations, "Restrict CORS to specific trusted origins")
			analysis.Score -= 2
		}

		// Check if credentials are allowed with wildcard
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		if acac == "true" && acao == "*" {
			analysis.CriticalIssues = append(analysis.CriticalIssues, "CRITICAL: CORS allows credentials with wildcard origin")
			analysis.Score -= 2
		}
	}
}

// checkInformationDisclosure checks for information disclosure in headers
func (a *Analyzer) checkInformationDisclosure(resp *http.Response, analysis *HeaderAnalysis) {
	// Check Server header
	server := resp.Header.Get("Server")
	if server != "" {
		analysis.PresentHeaders["Server"] = server
		if strings.Contains(strings.ToLower(server), "apache") ||
		   strings.Contains(strings.ToLower(server), "nginx") ||
		   strings.Contains(strings.ToLower(server), "microsoft-iis") {
			analysis.Warnings = append(analysis.Warnings, "Server header reveals web server technology")
		}
	}

	// Check X-Powered-By
	xpb := resp.Header.Get("X-Powered-By")
	if xpb != "" {
		analysis.PresentHeaders["X-Powered-By"] = xpb
		analysis.Warnings = append(analysis.Warnings, "X-Powered-By header reveals technology stack")
		analysis.Recommendations = append(analysis.Recommendations, "Remove X-Powered-By header to reduce information disclosure")
	}

	// Check X-AspNet-Version
	xav := resp.Header.Get("X-AspNet-Version")
	if xav != "" {
		analysis.PresentHeaders["X-AspNet-Version"] = xav
		analysis.Warnings = append(analysis.Warnings, "X-AspNet-Version reveals ASP.NET version")
		analysis.Recommendations = append(analysis.Recommendations, "Remove X-AspNet-Version header")
	}

	// Check X-AspNetMvc-Version
	xamv := resp.Header.Get("X-AspNetMvc-Version")
	if xamv != "" {
		analysis.PresentHeaders["X-AspNetMvc-Version"] = xamv
		analysis.Warnings = append(analysis.Warnings, "X-AspNetMvc-Version reveals MVC version")
		analysis.Recommendations = append(analysis.Recommendations, "Remove X-AspNetMvc-Version header")
	}
}

// calculateGrade calculates letter grade from score
func calculateGrade(score int) string {
	if score >= 9 {
		return "A+"
	} else if score >= 8 {
		return "A"
	} else if score >= 7 {
		return "B"
	} else if score >= 6 {
		return "C"
	} else if score >= 4 {
		return "D"
	}
	return "F"
}

// AnalyzeBatch analyzes multiple subdomains (sequential)
func (a *Analyzer) AnalyzeBatch(ctx context.Context, subdomains []string) map[string]*HeaderAnalysis {
	results := make(map[string]*HeaderAnalysis)

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		analysis := a.AnalyzeHeaders(ctx, subdomain)
		if analysis != nil {
			results[subdomain] = analysis
		}

		time.Sleep(100 * time.Millisecond)
	}

	return results
}

// GetPoorSecurityHosts returns hosts with grade D or F
func GetPoorSecurityHosts(results map[string]*HeaderAnalysis) []string {
	var poor []string
	for subdomain, analysis := range results {
		if analysis.Grade == "D" || analysis.Grade == "F" {
			poor = append(poor, subdomain)
		}
	}
	return poor
}
