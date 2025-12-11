package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// Analysis represents TLS/SSL analysis results
type Analysis struct {
	Subdomain        string    `json:"subdomain"`
	Enabled          bool      `json:"enabled"`
	Version          string    `json:"version"`
	CipherSuite      string    `json:"cipher_suite"`
	Certificate      CertInfo  `json:"certificate"`
	Vulnerabilities  []string  `json:"vulnerabilities"`
	Warnings         []string  `json:"warnings"`
	Grade            string    `json:"grade"` // A, B, C, D, F
}

// CertInfo represents certificate information
type CertInfo struct {
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	ValidFrom      time.Time `json:"valid_from"`
	ValidUntil     time.Time `json:"valid_until"`
	DNSNames       []string  `json:"dns_names"`
	IsExpired      bool      `json:"is_expired"`
	IsWildcard     bool      `json:"is_wildcard"`
	IsSelfSigned   bool      `json:"is_self_signed"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
}

// Analyzer performs TLS/SSL analysis
type Analyzer struct {
	timeout time.Duration
}

// NewAnalyzer creates a new TLS analyzer
func NewAnalyzer(timeout int) *Analyzer {
	return &Analyzer{
		timeout: time.Duration(timeout) * time.Second,
	}
}

// Analyze performs TLS/SSL analysis on a subdomain
func (a *Analyzer) Analyze(ctx context.Context, subdomain string) *Analysis {
	analysis := &Analysis{
		Subdomain: subdomain,
		Grade:     "F",
	}

	// Try to connect with TLS
	conn, err := tls.DialWithDialer(
		&net.Dialer{
			Timeout: a.timeout,
		},
		"tcp",
		subdomain+":443",
		&tls.Config{
			InsecureSkipVerify: true, // We want to analyze even invalid certs
			MinVersion:         tls.VersionSSL30, // Check for old protocols
		},
	)

	if err != nil {
		analysis.Enabled = false
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "TLS/HTTPS not enabled")
		return analysis
	}
	defer conn.Close()

	analysis.Enabled = true
	state := conn.ConnectionState()

	// Analyze TLS version
	a.analyzeTLSVersion(&state, analysis)

	// Analyze cipher suite
	a.analyzeCipherSuite(&state, analysis)

	// Analyze certificate
	if len(state.PeerCertificates) > 0 {
		a.analyzeCertificate(state.PeerCertificates[0], subdomain, analysis)
	}

	// Calculate grade
	analysis.Grade = a.calculateGrade(analysis)

	return analysis
}

// analyzeTLSVersion analyzes TLS version
func (a *Analyzer) analyzeTLSVersion(state *tls.ConnectionState, analysis *Analysis) {
	switch state.Version {
	case tls.VersionSSL30:
		analysis.Version = "SSL 3.0"
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "CRITICAL: SSL 3.0 is deprecated and vulnerable (POODLE)")

	case tls.VersionTLS10:
		analysis.Version = "TLS 1.0"
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "TLS 1.0 is deprecated and vulnerable")

	case tls.VersionTLS11:
		analysis.Version = "TLS 1.1"
		analysis.Warnings = append(analysis.Warnings, "TLS 1.1 is deprecated")

	case tls.VersionTLS12:
		analysis.Version = "TLS 1.2"
		// TLS 1.2 is acceptable

	case tls.VersionTLS13:
		analysis.Version = "TLS 1.3"
		// TLS 1.3 is best

	default:
		analysis.Version = "Unknown"
	}
}

// analyzeCipherSuite analyzes cipher suite
func (a *Analyzer) analyzeCipherSuite(state *tls.ConnectionState, analysis *Analysis) {
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)
	analysis.CipherSuite = cipherSuite

	// Check for weak ciphers
	weakCiphers := []string{
		"RC4",
		"DES",
		"3DES",
		"MD5",
		"NULL",
		"EXPORT",
		"anon",
	}

	cipherUpper := strings.ToUpper(cipherSuite)
	for _, weak := range weakCiphers {
		if strings.Contains(cipherUpper, strings.ToUpper(weak)) {
			analysis.Vulnerabilities = append(analysis.Vulnerabilities,
				fmt.Sprintf("Weak cipher suite in use: %s", weak))
			break
		}
	}

	// Check for CBC mode (BEAST, Lucky13 attacks)
	if strings.Contains(cipherUpper, "CBC") {
		analysis.Warnings = append(analysis.Warnings, "CBC mode cipher (vulnerable to BEAST/Lucky13)")
	}
}

// analyzeCertificate analyzes the TLS certificate
func (a *Analyzer) analyzeCertificate(cert *x509.Certificate, subdomain string, analysis *Analysis) {
	certInfo := CertInfo{
		Subject:    cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		ValidFrom:  cert.NotBefore,
		ValidUntil: cert.NotAfter,
		DNSNames:   cert.DNSNames,
	}

	// Check if expired
	now := time.Now()
	if now.After(cert.NotAfter) {
		certInfo.IsExpired = true
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "CRITICAL: Certificate is expired")
	} else if now.Before(cert.NotBefore) {
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "Certificate is not yet valid")
	}

	// Calculate days until expiry
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	certInfo.DaysUntilExpiry = daysUntilExpiry

	if !certInfo.IsExpired {
		if daysUntilExpiry < 30 {
			analysis.Warnings = append(analysis.Warnings,
				fmt.Sprintf("Certificate expires soon (%d days)", daysUntilExpiry))
		}
	}

	// Check for wildcard
	if strings.HasPrefix(cert.Subject.CommonName, "*.") {
		certInfo.IsWildcard = true
	}

	// Check for self-signed
	if cert.Subject.CommonName == cert.Issuer.CommonName {
		certInfo.IsSelfSigned = true
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "Certificate is self-signed")
	}

	// Check if certificate matches subdomain
	validForSubdomain := false
	if cert.Subject.CommonName == subdomain {
		validForSubdomain = true
	}

	for _, dnsName := range cert.DNSNames {
		if dnsName == subdomain {
			validForSubdomain = true
			break
		}
		// Check wildcard match
		if strings.HasPrefix(dnsName, "*.") {
			wildcardDomain := strings.TrimPrefix(dnsName, "*.")
			if strings.HasSuffix(subdomain, wildcardDomain) {
				validForSubdomain = true
				break
			}
		}
	}

	if !validForSubdomain {
		analysis.Warnings = append(analysis.Warnings, "Certificate CN/SAN doesn't match subdomain")
	}

	// Check weak signature algorithm
	sigAlgo := cert.SignatureAlgorithm.String()
	if strings.Contains(strings.ToLower(sigAlgo), "md5") ||
	   strings.Contains(strings.ToLower(sigAlgo), "sha1") {
		analysis.Vulnerabilities = append(analysis.Vulnerabilities,
			fmt.Sprintf("Weak signature algorithm: %s", sigAlgo))
	}

	// Check key size
	switch pubKey := cert.PublicKey.(type) {
	case *interface{}:
		_ = pubKey
		// RSA key size check would go here, but requires type assertion
	}

	analysis.Certificate = certInfo
}

// calculateGrade calculates overall TLS grade
func (a *Analyzer) calculateGrade(analysis *Analysis) string {
	score := 100

	// Deduct for vulnerabilities
	for _, vuln := range analysis.Vulnerabilities {
		if strings.Contains(vuln, "CRITICAL") {
			score -= 40
		} else if strings.Contains(vuln, "SSL") || strings.Contains(vuln, "TLS 1.0") {
			score -= 30
		} else if strings.Contains(vuln, "expired") || strings.Contains(vuln, "self-signed") {
			score -= 25
		} else {
			score -= 15
		}
	}

	// Deduct for warnings
	score -= len(analysis.Warnings) * 5

	// Bonus for TLS 1.3
	if analysis.Version == "TLS 1.3" {
		score += 10
	}

	// Calculate grade
	if score >= 90 {
		return "A"
	} else if score >= 80 {
		return "B"
	} else if score >= 70 {
		return "C"
	} else if score >= 60 {
		return "D"
	}
	return "F"
}

// AnalyzeBatch analyzes multiple subdomains (sequential)
func (a *Analyzer) AnalyzeBatch(ctx context.Context, subdomains []string) map[string]*Analysis {
	results := make(map[string]*Analysis)

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		analysis := a.Analyze(ctx, subdomain)
		if analysis != nil {
			results[subdomain] = analysis
		}

		time.Sleep(100 * time.Millisecond)
	}

	return results
}

// GetVulnerableHosts returns hosts with TLS vulnerabilities
func GetVulnerableHosts(results map[string]*Analysis) []string {
	var vulnerable []string
	for subdomain, analysis := range results {
		if len(analysis.Vulnerabilities) > 0 {
			vulnerable = append(vulnerable, subdomain)
		}
	}
	return vulnerable
}

// GetExpiringSoon returns hosts with certificates expiring within days
func GetExpiringSoon(results map[string]*Analysis, days int) []string {
	var expiring []string
	for subdomain, analysis := range results {
		if analysis.Certificate.DaysUntilExpiry > 0 &&
		   analysis.Certificate.DaysUntilExpiry <= days {
			expiring = append(expiring, subdomain)
		}
	}
	return expiring
}
