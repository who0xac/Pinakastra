package takeover

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Vulnerability represents a takeover vulnerability
type Vulnerability struct {
	Subdomain   string `json:"subdomain"`
	Service     string `json:"service"`
	CNAME       string `json:"cname"`
	Verified    bool   `json:"verified"`     // Properly verified
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`     // Response snippet proving vulnerability
}

// Checker performs subdomain takeover detection
type Checker struct {
	client       *http.Client
	dnsClient    *dns.Client
	dnsServer    string
	timeout      time.Duration
}

// NewChecker creates a new takeover checker
func NewChecker(timeout int) *Checker {
	return &Checker{
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
		dnsClient: &dns.Client{
			Timeout: 3 * time.Second,
		},
		dnsServer: "8.8.8.8:53",
		timeout:   time.Duration(timeout) * time.Second,
	}
}

// CheckSubdomain checks if a subdomain is vulnerable to takeover
// PROPER validation: CNAME + DNS resolution + HTTP response + content matching
func (c *Checker) CheckSubdomain(ctx context.Context, subdomain string) *Vulnerability {
	// Step 1: Get CNAME record
	cname := c.getCNAME(subdomain)
	if cname == "" {
		return nil // No CNAME, can't be vulnerable
	}

	// Step 2: Find matching fingerprint
	var matchedFingerprint *Fingerprint
	for i := range Fingerprints {
		for _, cnamePattern := range Fingerprints[i].CNAME {
			if strings.Contains(strings.ToLower(cname), strings.ToLower(cnamePattern)) {
				matchedFingerprint = &Fingerprints[i]
				break
			}
		}
		if matchedFingerprint != nil {
			break
		}
	}

	if matchedFingerprint == nil {
		return nil // CNAME doesn't match any known vulnerable service
	}

	// Step 3: Check if CNAME resolves
	// If CNAME doesn't resolve (NXDOMAIN), it's likely vulnerable
	resolves := c.checkCNAMEResolves(cname)

	// Step 4: Check HTTP response
	httpEvidence, statusCode := c.checkHTTPResponse(ctx, subdomain)

	// Step 5: Match response patterns
	isVulnerable := false
	evidence := ""

	for _, pattern := range matchedFingerprint.Response {
		if strings.Contains(httpEvidence, pattern) {
			isVulnerable = true
			evidence = pattern
			break
		}
	}

	// Additional check: if CNAME doesn't resolve + matches service pattern = vulnerable
	if !resolves && matchedFingerprint != nil {
		isVulnerable = true
		evidence = "CNAME points to non-existent resource"
	}

	// Check status code if fingerprint specifies one
	if matchedFingerprint.StatusCode != 0 {
		if statusCode != matchedFingerprint.StatusCode {
			isVulnerable = false // Status code doesn't match expected
		}
	}

	if !isVulnerable {
		return nil
	}

	return &Vulnerability{
		Subdomain:   subdomain,
		Service:     matchedFingerprint.Service,
		CNAME:       cname,
		Verified:    true,
		Severity:    matchedFingerprint.Severity,
		Description: fmt.Sprintf("Subdomain points to unclaimed %s resource", matchedFingerprint.Service),
		Evidence:    evidence,
	}
}

// getCNAME retrieves CNAME record for a subdomain
func (c *Checker) getCNAME(subdomain string) string {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(subdomain), dns.TypeCNAME)

	r, _, err := c.dnsClient.Exchange(m, c.dnsServer)
	if err != nil || r == nil {
		return ""
	}

	for _, ans := range r.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			return strings.TrimSuffix(cname.Target, ".")
		}
	}

	return ""
}

// checkCNAMEResolves checks if CNAME resolves to an IP
func (c *Checker) checkCNAMEResolves(cname string) bool {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(cname), dns.TypeA)

	r, _, err := c.dnsClient.Exchange(m, c.dnsServer)
	if err != nil || r == nil {
		return false
	}

	// Check for NXDOMAIN
	if r.Rcode == dns.RcodeNameError {
		return false
	}

	// Check if we got any A records
	for _, ans := range r.Answer {
		if _, ok := ans.(*dns.A); ok {
			return true
		}
	}

	return false
}

// checkHTTPResponse checks HTTP response from subdomain
func (c *Checker) checkHTTPResponse(ctx context.Context, subdomain string) (string, int) {
	// Try HTTPS first, then HTTP
	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024)) // 100KB max
		resp.Body.Close()

		return string(body), resp.StatusCode
	}

	return "", 0
}

// CheckBatch checks multiple subdomains (sequential to avoid rate limits)
func (c *Checker) CheckBatch(ctx context.Context, subdomains []string) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return vulnerabilities
		default:
		}

		vuln := c.CheckSubdomain(ctx, subdomain)
		if vuln != nil {
			vulnerabilities = append(vulnerabilities, *vuln)
		}

		// Small delay to avoid rate limiting
		time.Sleep(100 * time.Millisecond)
	}

	return vulnerabilities
}

// VerifyTakeover performs additional verification
func (c *Checker) VerifyTakeover(ctx context.Context, subdomain string) bool {
	// Double-check by trying to resolve via multiple DNS servers
	dnsServers := []string{
		"8.8.8.8:53",   // Google
		"1.1.1.1:53",   // Cloudflare
		"9.9.9.9:53",   // Quad9
	}

	cnames := make(map[string]int)

	for _, server := range dnsServers {
		client := &dns.Client{Timeout: 2 * time.Second}
		m := &dns.Msg{}
		m.SetQuestion(dns.Fqdn(subdomain), dns.TypeCNAME)

		r, _, err := client.Exchange(m, server)
		if err != nil || r == nil {
			continue
		}

		for _, ans := range r.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				cnameTarget := strings.TrimSuffix(cname.Target, ".")
				cnames[cnameTarget]++
			}
		}
	}

	// If majority of DNS servers return the same CNAME, it's consistent
	for cname, count := range cnames {
		if count >= 2 {
			// Check if this CNAME is vulnerable
			ips, err := net.LookupIP(cname)
			if err != nil || len(ips) == 0 {
				return true // CNAME doesn't resolve = vulnerable
			}
		}
	}

	return false
}

// GetCriticalVulnerabilities returns only critical/high severity findings
func GetCriticalVulnerabilities(vulns []Vulnerability) []Vulnerability {
	var critical []Vulnerability
	for _, v := range vulns {
		if v.Severity == "critical" || v.Severity == "high" {
			critical = append(critical, v)
		}
	}
	return critical
}

// GroupByService groups vulnerabilities by service
func GroupByService(vulns []Vulnerability) map[string][]Vulnerability {
	grouped := make(map[string][]Vulnerability)
	for _, v := range vulns {
		grouped[v.Service] = append(grouped[v.Service], v)
	}
	return grouped
}
